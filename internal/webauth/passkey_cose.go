// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package webauth

import (
	"errors"
	"fmt"
)

var ErrInvalidPasskeyCredentialKeyCOSE = errors.New("invalid passkey credential key COSE")

type PasskeyCredentialKeyMetadata struct {
	KTY       int    `json:"kty"`
	Algorithm int    `json:"algorithm"`
	Curve     int    `json:"curve,omitempty"`
	Type      string `json:"type"`
}

func ParsePasskeyCredentialKeyCOSE(raw []byte) (PasskeyCredentialKeyMetadata, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return PasskeyCredentialKeyMetadata{}, ErrInvalidPasskeyCredentialKeyCOSE
	}
	decoder := coseDecoder{data: raw}
	intValues, bytesValues, err := decoder.readMap()
	if err != nil || decoder.offset != len(raw) {
		return PasskeyCredentialKeyMetadata{}, ErrInvalidPasskeyCredentialKeyCOSE
	}
	kty, ok := intValues[1]
	if !ok {
		return PasskeyCredentialKeyMetadata{}, ErrInvalidPasskeyCredentialKeyCOSE
	}
	algorithm, ok := intValues[3]
	if !ok {
		return PasskeyCredentialKeyMetadata{}, ErrInvalidPasskeyCredentialKeyCOSE
	}
	switch kty {
	case 2: // EC2
		curve, ok := intValues[-1]
		if !ok || curve != 1 || algorithm != -7 || len(bytesValues[-2]) != 32 || len(bytesValues[-3]) != 32 {
			return PasskeyCredentialKeyMetadata{}, ErrInvalidPasskeyCredentialKeyCOSE
		}
		return PasskeyCredentialKeyMetadata{KTY: kty, Algorithm: algorithm, Curve: curve, Type: "ec2_p256_es256"}, nil
	case 3: // RSA
		if algorithm != -257 || len(bytesValues[-1]) < 256 || len(bytesValues[-2]) == 0 {
			return PasskeyCredentialKeyMetadata{}, ErrInvalidPasskeyCredentialKeyCOSE
		}
		return PasskeyCredentialKeyMetadata{KTY: kty, Algorithm: algorithm, Type: "rsa_rs256"}, nil
	default:
		return PasskeyCredentialKeyMetadata{}, ErrInvalidPasskeyCredentialKeyCOSE
	}
}

type coseDecoder struct {
	data   []byte
	offset int
}

func (d *coseDecoder) readMap() (map[int]int, map[int][]byte, error) {
	major, length, err := d.readTypeAndLength()
	if err != nil || major != 5 {
		return nil, nil, fmt.Errorf("expected map")
	}
	intValues := map[int]int{}
	bytesValues := map[int][]byte{}
	for i := 0; i < length; i++ {
		key, err := d.readInt()
		if err != nil {
			return nil, nil, err
		}
		major, _, err := d.peekTypeAndLength()
		if err != nil {
			return nil, nil, err
		}
		switch major {
		case 0, 1:
			value, err := d.readInt()
			if err != nil {
				return nil, nil, err
			}
			intValues[key] = value
		case 2:
			value, err := d.readByteString()
			if err != nil {
				return nil, nil, err
			}
			bytesValues[key] = value
		default:
			return nil, nil, fmt.Errorf("unsupported COSE value type")
		}
	}
	return intValues, bytesValues, nil
}

func (d *coseDecoder) readInt() (int, error) {
	major, value, err := d.readTypeAndLength()
	if err != nil {
		return 0, err
	}
	switch major {
	case 0:
		return value, nil
	case 1:
		return -1 - value, nil
	default:
		return 0, fmt.Errorf("expected int")
	}
}

func (d *coseDecoder) readByteString() ([]byte, error) {
	major, length, err := d.readTypeAndLength()
	if err != nil || major != 2 || length < 0 || d.offset+length > len(d.data) {
		return nil, fmt.Errorf("invalid bytes")
	}
	value := make([]byte, length)
	copy(value, d.data[d.offset:d.offset+length])
	d.offset += length
	return value, nil
}

func (d *coseDecoder) peekTypeAndLength() (int, int, error) {
	offset := d.offset
	major, length, err := d.readTypeAndLength()
	d.offset = offset
	return major, length, err
}

func (d *coseDecoder) readTypeAndLength() (int, int, error) {
	if d.offset >= len(d.data) {
		return 0, 0, fmt.Errorf("unexpected EOF")
	}
	initial := d.data[d.offset]
	d.offset++
	major := int(initial >> 5)
	additional := int(initial & 0x1f)
	switch {
	case additional < 24:
		return major, additional, nil
	case additional == 24:
		if d.offset >= len(d.data) {
			return 0, 0, fmt.Errorf("unexpected EOF")
		}
		value := int(d.data[d.offset])
		d.offset++
		return major, value, nil
	case additional == 25:
		if d.offset+2 > len(d.data) {
			return 0, 0, fmt.Errorf("unexpected EOF")
		}
		value := int(d.data[d.offset])<<8 | int(d.data[d.offset+1])
		d.offset += 2
		return major, value, nil
	default:
		return 0, 0, fmt.Errorf("unsupported length")
	}
}
