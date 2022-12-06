package provider

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

func random32() (string, error) {
	b := make([]byte, 32)
	if err := binary.Read(rand.Reader, binary.LittleEndian, b); err != nil {
		return "", fmt.Errorf("random32 error: %w", err)
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}
