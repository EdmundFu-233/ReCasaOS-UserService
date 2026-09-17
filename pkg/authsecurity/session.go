package authsecurity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

const (
	// AccessTokenLifetime and RefreshTokenLifetime preserve the lifetimes the
	// CasaOS-Common minters assign, so existing clients keep their refresh
	// cadence after the migration to versioned session claims.
	AccessTokenLifetime  = 3 * time.Hour
	RefreshTokenLifetime = 7 * 24 * time.Hour

	maxSessionTokenIDBytes = 16
)

// SessionClaims carries the CasaOS access/refresh identity fields plus the
// session controls the gateway ignores when it parses the same token with the
// shared CasaOS-Common claims shape: a unique token identifier (jti) and the
// user's credential generation (token_version).
type SessionClaims struct {
	jwt.RegisteredClaims
	Username     string `json:"username"`
	UserID       int    `json:"id"`
	TokenVersion int    `json:"token_version"`
}

var (
	ErrInvalidSessionToken = errors.New("invalid session token")
	ErrSessionTokenID      = errors.New("session token identifier is unavailable")
)

// NewTokenID returns a 128-bit random token identifier for the jti claim.
func NewTokenID() (string, error) {
	raw := make([]byte, maxSessionTokenIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", ErrSessionTokenID
	}
	return hex.EncodeToString(raw), nil
}

// TokenSHA256 binds a refresh token to its session row without persisting
// anything that could impersonate the session on its own.
func TokenSHA256(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

// MintAccessToken issues a short-lived access token for one session.
func MintAccessToken(username string, userID, tokenVersion int, tokenID string, privateKey *ecdsa.PrivateKey) (string, error) {
	return mintSessionToken(username, userID, tokenVersion, tokenID, AccessTokenIssuer, AccessTokenLifetime, privateKey)
}

// MintRefreshToken issues a long-lived refresh token for one session.
func MintRefreshToken(username string, userID, tokenVersion int, tokenID string, privateKey *ecdsa.PrivateKey) (string, error) {
	return mintSessionToken(username, userID, tokenVersion, tokenID, RefreshTokenIssuer, RefreshTokenLifetime, privateKey)
}

func mintSessionToken(username string, userID, tokenVersion int, tokenID, issuer string, lifetime time.Duration, privateKey *ecdsa.PrivateKey) (string, error) {
	if username == "" || userID < 1 || tokenID == "" || tokenVersion < 0 || privateKey == nil {
		return "", ErrInvalidSessionToken
	}
	now := time.Now()
	claims := SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   username,
			ID:        tokenID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(lifetime)),
		},
		Username:     username,
		UserID:       userID,
		TokenVersion: tokenVersion,
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return signed, nil
}

// ValidateSessionAccessToken verifies the signature, time-based claims, and
// access-token class of a versioned session token.
func ValidateSessionAccessToken(
	token string,
	publicKey func() (*ecdsa.PublicKey, error),
) (*SessionClaims, error) {
	return validateSessionToken(token, AccessTokenIssuer, publicKey)
}

// ValidateSessionRefreshToken applies the same checks while requiring the
// refresh-token issuer. Callers must additionally confirm the session row
// before minting replacement credentials.
func ValidateSessionRefreshToken(
	token string,
	publicKey func() (*ecdsa.PublicKey, error),
) (*SessionClaims, error) {
	return validateSessionToken(token, RefreshTokenIssuer, publicKey)
}

func validateSessionToken(
	token string,
	issuer string,
	publicKey func() (*ecdsa.PublicKey, error),
) (*SessionClaims, error) {
	if token == "" || len(token) > maxTokenSize || publicKey == nil {
		return nil, ErrInvalidSessionToken
	}
	claims := &SessionClaims{}
	parsed, err := jwt.ParseWithClaims(
		token,
		claims,
		func(parsed *jwt.Token) (interface{}, error) {
			if parsed == nil || parsed.Method != jwt.SigningMethodES256 {
				return nil, ErrInvalidSessionToken
			}
			key, err := publicKey()
			if err != nil || key == nil || key.Curve != elliptic.P256() ||
				key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
				return nil, ErrInvalidSessionToken
			}
			return key, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
	)
	if err != nil || parsed == nil || !parsed.Valid || parsed.Claims != claims ||
		claims.Issuer != issuer || claims.ID == "" || claims.UserID < 1 ||
		claims.Username == "" || claims.TokenVersion < 0 ||
		claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.NotBefore == nil {
		return nil, ErrInvalidSessionToken
	}
	return claims, nil
}
