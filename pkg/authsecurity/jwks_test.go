package authsecurity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

func TestGeneratePublicJWKSUsesFixedWidthPublicCoordinates(t *testing.T) {
	publicKey := p256KeyWithShortBigIntCoordinate(t)
	encoded, err := GeneratePublicJWKS(publicKey)
	if err != nil {
		t.Fatalf("GeneratePublicJWKS(): %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("JWKS root field count = %d, want 1", len(decoded))
	}
	keys, ok := decoded["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("JWKS keys = %#v, want one key", decoded["keys"])
	}
	key, ok := keys[0].(map[string]any)
	if !ok || len(key) != 4 || key["kty"] != "EC" || key["crv"] != "P-256" {
		t.Fatalf("JWK public fields are not exact")
	}
	if _, exists := key["d"]; exists {
		t.Fatal("JWK exposes a private coordinate")
	}
	for _, name := range []string{"x", "y"} {
		value, ok := key[name].(string)
		if !ok {
			t.Fatalf("JWK %s is not a string", name)
		}
		coordinate, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil {
			t.Fatalf("decode JWK %s: %v", name, err)
		}
		if len(coordinate) != p256CoordinateBytes {
			t.Fatalf("JWK %s length = %d, want %d", name, len(coordinate), p256CoordinateBytes)
		}
	}
}

func TestGeneratePublicJWKSRejectsInvalidKeys(t *testing.T) {
	tests := []struct {
		name string
		key  *ecdsa.PublicKey
	}{
		{name: "nil"},
		{name: "wrong curve", key: &ecdsa.PublicKey{Curve: elliptic.P384(), X: big.NewInt(1), Y: big.NewInt(1)}},
		{name: "off curve", key: &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := GeneratePublicJWKS(test.key); err == nil {
				t.Fatal("GeneratePublicJWKS() unexpectedly succeeded")
			}
		})
	}
}

func p256KeyWithShortBigIntCoordinate(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	curve := elliptic.P256()
	for scalar := int64(1); scalar < 100_000; scalar++ {
		x, y := curve.ScalarBaseMult(big.NewInt(scalar).Bytes())
		if len(x.Bytes()) < p256CoordinateBytes || len(y.Bytes()) < p256CoordinateBytes {
			return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		}
	}
	t.Fatal("could not find a deterministic P-256 point with a short big.Int coordinate")
	return nil
}
