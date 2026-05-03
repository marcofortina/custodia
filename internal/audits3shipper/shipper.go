package audits3shipper

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"custodia/internal/auditarchive"
	"custodia/internal/auditartifact"
)

var (
	ErrInvalidConfig     = errors.New("invalid S3 audit shipment configuration")
	ErrObjectLockMissing = errors.New("S3 object lock retention is required")
)

type Config struct {
	Endpoint        string
	Region          string
	Bucket          string
	Prefix          string
	AccessKeyID     string
	SecretAccessKey string
	ObjectLockMode  string
	RetainUntil     time.Time
	Client          *http.Client
	Now             func() time.Time
}

type ObjectResult struct {
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
	Status int    `json:"status"`
}

type ShipmentResult struct {
	Bucket       string                     `json:"bucket"`
	Prefix       string                     `json:"prefix"`
	Objects      map[string]ObjectResult    `json:"objects"`
	Verification auditartifact.Verification `json:"verification"`
}

func ShipArchive(ctx context.Context, archiveDir string, cfg Config) (ShipmentResult, error) {
	if err := cfg.validate(); err != nil {
		return ShipmentResult{}, err
	}
	manifest, err := readArchiveManifest(archiveDir)
	if err != nil {
		return ShipmentResult{}, err
	}
	files := map[string]string{
		manifest.ExportFile: manifest.ExportFile,
		manifest.SHA256File: manifest.SHA256File,
		manifest.EventsFile: manifest.EventsFile,
		"manifest.json":     "manifest.json",
	}
	body, err := os.ReadFile(filepath.Join(archiveDir, manifest.ExportFile))
	if err != nil {
		return ShipmentResult{}, err
	}
	expectedDigest, err := os.ReadFile(filepath.Join(archiveDir, manifest.SHA256File))
	if err != nil {
		return ShipmentResult{}, err
	}
	expectedEvents, err := os.ReadFile(filepath.Join(archiveDir, manifest.EventsFile))
	if err != nil {
		return ShipmentResult{}, err
	}
	verification, err := auditartifact.Verify(body, string(expectedDigest), string(expectedEvents))
	if err != nil {
		return ShipmentResult{}, err
	}
	objects := make(map[string]ObjectResult)
	for name := range files {
		data, err := os.ReadFile(filepath.Join(archiveDir, name))
		if err != nil {
			return ShipmentResult{}, err
		}
		key := objectKey(cfg.Prefix, filepath.Base(archiveDir), name)
		status, digest, err := cfg.putObject(ctx, key, data)
		if err != nil {
			return ShipmentResult{}, err
		}
		objects[name] = ObjectResult{Key: key, SHA256: digest, Status: status}
	}
	return ShipmentResult{Bucket: cfg.Bucket, Prefix: strings.Trim(cfg.Prefix, "/"), Objects: objects, Verification: verification}, nil
}

func (cfg Config) validate() error {
	if strings.TrimSpace(cfg.Endpoint) == "" || strings.TrimSpace(cfg.Region) == "" || strings.TrimSpace(cfg.Bucket) == "" || strings.TrimSpace(cfg.AccessKeyID) == "" || strings.TrimSpace(cfg.SecretAccessKey) == "" {
		return ErrInvalidConfig
	}
	if strings.TrimSpace(cfg.ObjectLockMode) == "" || cfg.RetainUntil.IsZero() {
		return ErrObjectLockMissing
	}
	if _, err := url.ParseRequestURI(cfg.Endpoint); err != nil {
		return ErrInvalidConfig
	}
	return nil
}

func readArchiveManifest(dir string) (auditarchive.Manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return auditarchive.Manifest{}, err
	}
	var manifest auditarchive.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return auditarchive.Manifest{}, err
	}
	if manifest.ExportFile == "" || manifest.SHA256File == "" || manifest.EventsFile == "" {
		return auditarchive.Manifest{}, fmt.Errorf("archive manifest is incomplete")
	}
	return manifest, nil
}

func objectKey(prefix, archiveName, filename string) string {
	parts := []string{}
	if trimmed := strings.Trim(prefix, "/"); trimmed != "" {
		parts = append(parts, trimmed)
	}
	parts = append(parts, archiveName, filename)
	return path.Join(parts...)
}

func (cfg Config) putObject(ctx context.Context, key string, body []byte) (int, string, error) {
	client := cfg.Client
	if client == nil {
		client = http.DefaultClient
	}
	endpoint, err := url.Parse(strings.TrimRight(cfg.Endpoint, "/"))
	if err != nil {
		return 0, "", err
	}
	endpoint.Path = path.Join(endpoint.Path, cfg.Bucket, key)
	digest := sha256.Sum256(body)
	digestHex := hex.EncodeToString(digest[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	now := time.Now().UTC()
	if cfg.Now != nil {
		now = cfg.Now().UTC()
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Amz-Content-Sha256", digestHex)
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
	req.Header.Set("X-Amz-Object-Lock-Mode", strings.ToUpper(strings.TrimSpace(cfg.ObjectLockMode)))
	req.Header.Set("X-Amz-Object-Lock-Retain-Until-Date", cfg.RetainUntil.UTC().Format(time.RFC3339))
	signRequest(req, cfg, digestHex, now)
	res, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return res.StatusCode, digestHex, fmt.Errorf("S3 put object failed: %s", res.Status)
	}
	return res.StatusCode, digestHex, nil
}

func signRequest(req *http.Request, cfg Config, payloadHash string, now time.Time) {
	date := now.Format("20060102")
	credentialScope := date + "/" + cfg.Region + "/s3/aws4_request"
	signedHeaders := []string{"content-type", "host", "x-amz-content-sha256", "x-amz-date", "x-amz-object-lock-mode", "x-amz-object-lock-retain-until-date"}
	headers := map[string]string{
		"content-type":                        req.Header.Get("Content-Type"),
		"host":                                req.URL.Host,
		"x-amz-content-sha256":                req.Header.Get("X-Amz-Content-Sha256"),
		"x-amz-date":                          req.Header.Get("X-Amz-Date"),
		"x-amz-object-lock-mode":              req.Header.Get("X-Amz-Object-Lock-Mode"),
		"x-amz-object-lock-retain-until-date": req.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"),
	}
	sort.Strings(signedHeaders)
	canonicalHeaders := ""
	for _, header := range signedHeaders {
		canonicalHeaders += header + ":" + strings.TrimSpace(headers[header]) + "\n"
	}
	canonicalRequest := strings.Join([]string{
		req.Method,
		escapePath(req.URL.EscapedPath()),
		"",
		canonicalHeaders,
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n")
	canonicalHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		now.Format("20060102T150405Z"),
		credentialScope,
		hex.EncodeToString(canonicalHash[:]),
	}, "\n")
	signingKey := awsSigningKey(cfg.SecretAccessKey, date, cfg.Region)
	signature := hmacSHA256Hex(signingKey, stringToSign)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+cfg.AccessKeyID+"/"+credentialScope+", SignedHeaders="+strings.Join(signedHeaders, ";")+", Signature="+signature)
}

func escapePath(value string) string {
	if value == "" {
		return "/"
	}
	return value
}

func awsSigningKey(secret, date, region string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, "s3")
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func hmacSHA256Hex(key []byte, value string) string {
	return hex.EncodeToString(hmacSHA256(key, value))
}
