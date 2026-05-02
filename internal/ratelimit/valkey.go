package ratelimit

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ValkeyLimiter struct {
	address  string
	useTLS   bool
	password string
}

func NewValkeyLimiter(rawURL string) (*ValkeyLimiter, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "redis" && parsed.Scheme != "rediss" {
		return nil, errors.New("valkey URL must use redis:// or rediss://")
	}
	password := ""
	if parsed.User != nil {
		password, _ = parsed.User.Password()
	}
	return &ValkeyLimiter{address: parsed.Host, useTLS: parsed.Scheme == "rediss", password: password}, nil
}

func (l *ValkeyLimiter) Allow(ctx context.Context, key string, limit int) (bool, error) {
	if limit <= 0 {
		return true, nil
	}
	redisKey := fmt.Sprintf("custodia:rl:%s:%d", key, time.Now().Unix())
	conn, err := l.dial(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if err := l.authenticate(conn, reader); err != nil {
		return false, err
	}
	if err := writeCommand(conn, "INCR", redisKey); err != nil {
		return false, err
	}
	count, err := readInteger(reader)
	if err != nil {
		return false, err
	}
	if count == 1 {
		if err := writeCommand(conn, "EXPIRE", redisKey, "2"); err == nil {
			_, _ = readInteger(reader)
		}
	}
	return count <= int64(limit), nil
}

func (l *ValkeyLimiter) Health(ctx context.Context) error {
	conn, err := l.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if err := l.authenticate(conn, reader); err != nil {
		return err
	}
	if err := writeCommand(conn, "PING"); err != nil {
		return err
	}
	_, err = readSimple(reader)
	return err
}

func (l *ValkeyLimiter) authenticate(conn net.Conn, reader *bufio.Reader) error {
	if l.password == "" {
		return nil
	}
	if err := writeCommand(conn, "AUTH", l.password); err != nil {
		return err
	}
	_, err := readSimple(reader)
	return err
}

func (l *ValkeyLimiter) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	if l.useTLS {
		return tls.DialWithDialer(dialer, "tcp", l.address, &tls.Config{MinVersion: tls.VersionTLS12})
	}
	return dialer.DialContext(ctx, "tcp", l.address)
}

func writeCommand(conn net.Conn, args ...string) error {
	var builder strings.Builder
	builder.WriteString("*")
	builder.WriteString(strconv.Itoa(len(args)))
	builder.WriteString("\r\n")
	for _, arg := range args {
		builder.WriteString("$")
		builder.WriteString(strconv.Itoa(len(arg)))
		builder.WriteString("\r\n")
		builder.WriteString(arg)
		builder.WriteString("\r\n")
	}
	_, err := conn.Write([]byte(builder.String()))
	return err
}

func readInteger(reader *bufio.Reader) (int64, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "-") {
		return 0, errors.New(line[1:])
	}
	if !strings.HasPrefix(line, ":") {
		return 0, fmt.Errorf("expected integer response, got %q", line)
	}
	return strconv.ParseInt(strings.TrimPrefix(line, ":"), 10, 64)
}

func readSimple(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "-") {
		return "", errors.New(line[1:])
	}
	return line, nil
}
