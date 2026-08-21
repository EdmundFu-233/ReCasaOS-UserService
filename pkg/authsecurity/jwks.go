package authsecurity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
)

const p256CoordinateBytes = 32

type publicJWK struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
	Y       string `json:"y"`
}

type publicJWKS struct {
	Keys []publicJWK `json:"keys"`
}

// GeneratePublicJWKS serializes one P-256 public key without private fields.
// Coordinates are left-padded to the fixed 32-byte width required for P-256,
// including the uncommon case where big.Int.Bytes omits leading zero octets.
func GeneratePublicJWKS(publicKey *ecdsa.PublicKey) ([]byte, error) {
	if publicKey == nil || publicKey.Curve != elliptic.P256() ||
		publicKey.X == nil || publicKey.Y == nil ||
		!publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, errors.New("JWKS requires a valid P-256 public key")
	}
	x := publicKey.X.FillBytes(make([]byte, p256CoordinateBytes))
	y := publicKey.Y.FillBytes(make([]byte, p256CoordinateBytes))
	return json.Marshal(publicJWKS{Keys: []publicJWK{{
		KeyType: "EC",
		Curve:   "P-256",
		X:       base64.RawURLEncoding.EncodeToString(x),
		Y:       base64.RawURLEncoding.EncodeToString(y),
	}}})
}
