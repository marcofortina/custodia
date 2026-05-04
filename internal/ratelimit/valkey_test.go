// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package ratelimit

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNewValkeyLimiterParsesRedisURLs(t *testing.T) {
	limiter, err := NewValkeyLimiter("rediss://:secret@cache.example:6380/0")
	if err != nil {
		t.Fatalf("NewValkeyLimiter() error = %v", err)
	}
	if limiter.address != "cache.example:6380" || !limiter.useTLS || limiter.password != "secret" {
		t.Fatalf("unexpected limiter config: %+v", limiter)
	}
}

func TestNewValkeyLimiterRejectsUnsupportedScheme(t *testing.T) {
	if _, err := NewValkeyLimiter("http://cache.example:6379"); err == nil {
		t.Fatal("expected unsupported scheme error")
	}
}

func TestWriteCommandUsesRESPArray(t *testing.T) {
	conn := &writeOnlyConn{}
	if err := writeCommand(conn, "INCR", "custodia:rl:key"); err != nil {
		t.Fatalf("writeCommand() error = %v", err)
	}
	want := "*2\r\n$4\r\nINCR\r\n$15\r\ncustodia:rl:key\r\n"
	if conn.String() != want {
		t.Fatalf("writeCommand() = %q, want %q", conn.String(), want)
	}
}

func TestReadInteger(t *testing.T) {
	got, err := readInteger(bufio.NewReader(strings.NewReader(":42\r\n")))
	if err != nil || got != 42 {
		t.Fatalf("readInteger() = %d, %v", got, err)
	}
	if _, err := readInteger(bufio.NewReader(strings.NewReader("-ERR nope\r\n"))); err == nil {
		t.Fatal("expected Redis error response to fail")
	}
	if _, err := readInteger(bufio.NewReader(strings.NewReader("+OK\r\n"))); err == nil {
		t.Fatal("expected non-integer response to fail")
	}
}

func TestReadSimple(t *testing.T) {
	got, err := readSimple(bufio.NewReader(strings.NewReader("+PONG\r\n")))
	if err != nil || got != "+PONG" {
		t.Fatalf("readSimple() = %q, %v", got, err)
	}
	if _, err := readSimple(bufio.NewReader(strings.NewReader("-NOAUTH required\r\n"))); err == nil {
		t.Fatal("expected Redis error response to fail")
	}
}

type writeOnlyConn struct {
	bytes.Buffer
}

func (c *writeOnlyConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *writeOnlyConn) Close() error                     { return nil }
func (c *writeOnlyConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *writeOnlyConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *writeOnlyConn) SetDeadline(time.Time) error      { return nil }
func (c *writeOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *writeOnlyConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }
