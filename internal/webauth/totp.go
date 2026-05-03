package webauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	TOTPPeriodSeconds = 30
	TOTPDigits        = 6
	TOTPSecretBytes   = 20
)

var (
	ErrInvalidTOTPSecret = errors.New("invalid TOTP secret")
	ErrInvalidTOTPCode   = errors.New("invalid TOTP code")
)

func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, TOTPSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

func TOTPCode(secret string, now time.Time) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	counter := uint64(now.Unix() / TOTPPeriodSeconds)
	return hotp(key, counter), nil
}

func VerifyTOTP(secret, code string, now time.Time, window int) bool {
	code = strings.TrimSpace(code)
	if !validTOTPCodeFormat(code) || window < 0 {
		return false
	}
	for offset := -window; offset <= window; offset++ {
		candidate, err := TOTPCode(secret, now.Add(time.Duration(offset*TOTPPeriodSeconds)*time.Second))
		if err != nil {
			return false
		}
		if hmac.Equal([]byte(candidate), []byte(code)) {
			return true
		}
	}
	return false
}

func TOTPProvisioningURI(issuer, account, secret string) (string, error) {
	if _, err := decodeTOTPSecret(secret); err != nil {
		return "", err
	}
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)
	if issuer == "" || account == "" {
		return "", ErrInvalidTOTPSecret
	}
	label := url.PathEscape(issuer + ":" + account)
	query := url.Values{}
	query.Set("secret", strings.ToUpper(strings.TrimSpace(secret)))
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", fmt.Sprintf("%d", TOTPDigits))
	query.Set("period", fmt.Sprintf("%d", TOTPPeriodSeconds))
	return "otpauth://totp/" + label + "?" + query.Encode(), nil
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	secret = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if secret == "" {
		return nil, ErrInvalidTOTPSecret
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(decoded) < 10 {
		return nil, ErrInvalidTOTPSecret
	}
	return decoded, nil
}

func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binaryCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	otp := binaryCode % 1000000
	return fmt.Sprintf("%06d", otp)
}

func validTOTPCodeFormat(code string) bool {
	if len(code) != TOTPDigits {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
