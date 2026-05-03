package webauth

import "testing"

func TestParsePasskeyCredentialKeyCOSEAcceptsES256(t *testing.T) {
	metadata, err := ParsePasskeyCredentialKeyCOSE(testES256COSEKey())
	if err != nil {
		t.Fatalf("ParsePasskeyCredentialKeyCOSE() error = %v", err)
	}
	if metadata.KTY != 2 || metadata.Algorithm != -7 || metadata.Curve != 1 || metadata.Type != "ec2_p256_es256" {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
}

func TestParsePasskeyCredentialKeyCOSERejectsMalformedKey(t *testing.T) {
	cases := [][]byte{
		nil,
		{0xa0},
		{0xa1, 0x01, 0x02},
		{0xa5, 0x01, 0x02, 0x03, 0x25, 0x20, 0x01, 0x21, 0x41, 0x01, 0x22, 0x41, 0x02},
	}
	for _, tc := range cases {
		if _, err := ParsePasskeyCredentialKeyCOSE(tc); err != ErrInvalidPasskeyCredentialKeyCOSE {
			t.Fatalf("ParsePasskeyCredentialKeyCOSE(%x) error = %v, want %v", tc, err, ErrInvalidPasskeyCredentialKeyCOSE)
		}
	}
}

func testES256COSEKey() []byte {
	key := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	for i := 0; i < 32; i++ {
		key = append(key, byte(i+1))
	}
	key = append(key, 0x22, 0x58, 0x20)
	for i := 0; i < 32; i++ {
		key = append(key, byte(i+33))
	}
	return key
}
