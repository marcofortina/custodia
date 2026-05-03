package webauth

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
)

var ErrInvalidPasskeyAuthenticatorData = errors.New("invalid passkey authenticator data")

type PasskeyAuthenticatorData struct {
	RPIDHash      []byte `json:"rp_id_hash"`
	Flags         byte   `json:"flags"`
	SignCount     uint32 `json:"sign_count"`
	UserPresent   bool   `json:"user_present"`
	UserVerified  bool   `json:"user_verified"`
	AttestedData  bool   `json:"attested_data"`
	ExtensionData bool   `json:"extension_data"`
}

func ParsePasskeyAuthenticatorData(raw []byte) (*PasskeyAuthenticatorData, error) {
	if len(raw) < 37 {
		return nil, ErrInvalidPasskeyAuthenticatorData
	}
	rpIDHash := make([]byte, 32)
	copy(rpIDHash, raw[:32])
	flags := raw[32]
	return &PasskeyAuthenticatorData{
		RPIDHash:      rpIDHash,
		Flags:         flags,
		SignCount:     binary.BigEndian.Uint32(raw[33:37]),
		UserPresent:   flags&0x01 != 0,
		UserVerified:  flags&0x04 != 0,
		AttestedData:  flags&0x40 != 0,
		ExtensionData: flags&0x80 != 0,
	}, nil
}

func ParsePasskeyAuthenticatorDataBase64URL(value string) (*PasskeyAuthenticatorData, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrInvalidPasskeyAuthenticatorData
	}
	return ParsePasskeyAuthenticatorData(raw)
}

func ValidatePasskeySignCount(previous, current uint32) error {
	if previous == 0 {
		return nil
	}
	if current <= previous {
		return ErrInvalidPasskeyAuthenticatorData
	}
	return nil
}
