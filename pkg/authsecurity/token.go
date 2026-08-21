package authsecurity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"

	commonjwt "github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	jwt "github.com/golang-jwt/jwt/v4"
)

const (
	AccessTokenIssuer  = "casaos"
	RefreshTokenIssuer = "refresh"
	maxTokenSize       = 8 << 10
)

var (
	ErrInvalidAccessToken  = errors.New("invalid access token")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

// ValidateAccessToken verifies the signature, time-based claims, and token
// class. CasaOS access and refresh tokens share a signing key, so signature
// validation alone is not sufficient authorization evidence.
func ValidateAccessToken(
	token string,
	publicKey func() (*ecdsa.PublicKey, error),
) (*commonjwt.Claims, error) {
	return validateToken(token, AccessTokenIssuer, publicKey, ErrInvalidAccessToken)
}

// ValidateRefreshToken applies the same cryptographic and identity checks as
// access-token validation while requiring the refresh-token issuer. Callers
// must additionally confirm that the referenced user still exists before
// minting replacement credentials.
func ValidateRefreshToken(
	token string,
	publicKey func() (*ecdsa.PublicKey, error),
) (*commonjwt.Claims, error) {
	return validateToken(token, RefreshTokenIssuer, publicKey, ErrInvalidRefreshToken)
}

func validateToken(
	token string,
	issuer string,
	publicKey func() (*ecdsa.PublicKey, error),
	invalidError error,
) (*commonjwt.Claims, error) {
	if token == "" || len(token) > maxTokenSize || publicKey == nil {
		return nil, invalidError
	}
	claims := &commonjwt.Claims{}
	parsed, err := jwt.ParseWithClaims(
		token,
		claims,
		func(parsed *jwt.Token) (interface{}, error) {
			if parsed == nil || parsed.Method != jwt.SigningMethodES256 {
				return nil, invalidError
			}
			key, err := publicKey()
			if err != nil || key == nil || key.Curve != elliptic.P256() ||
				key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
				return nil, invalidError
			}
			return key, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
	)
	if err != nil || parsed == nil || !parsed.Valid || parsed.Claims != claims ||
		claims.Issuer != issuer || claims.ID < 1 || claims.Username == "" ||
		claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.NotBefore == nil {
		return nil, invalidError
	}
	return claims, nil
}
