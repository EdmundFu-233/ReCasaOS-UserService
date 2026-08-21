package authsecurity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	commonjwt "github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	jwt "github.com/golang-jwt/jwt/v4"
)

func TestValidateAccessTokenSeparatesAccessAndRefreshTokens(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := func() (*ecdsa.PublicKey, error) {
		return &privateKey.PublicKey, nil
	}

	accessToken, err := commonjwt.GetAccessToken("admin", privateKey, 42)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ValidateAccessToken(accessToken, publicKey)
	if err != nil {
		t.Fatalf("access token rejected: %v", err)
	}
	if claims.ID != 42 || claims.Username != "admin" {
		t.Fatalf("unexpected claims: %#v", claims)
	}

	refreshToken, err := commonjwt.GetRefreshToken("admin", privateKey, 42)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAccessToken(refreshToken, publicKey); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("refresh token error = %v, want ErrInvalidAccessToken", err)
	}
}

func TestValidateRefreshTokenRequiresRefreshClassAndStrictIdentity(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := func() (*ecdsa.PublicKey, error) {
		return &privateKey.PublicKey, nil
	}

	refreshToken, err := commonjwt.GetRefreshToken("admin", privateKey, 42)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ValidateRefreshToken(refreshToken, publicKey)
	if err != nil {
		t.Fatalf("refresh token rejected: %v", err)
	}
	if claims.ID != 42 || claims.Username != "admin" {
		t.Fatalf("unexpected claims: %#v", claims)
	}

	accessToken, err := commonjwt.GetAccessToken("admin", privateKey, 42)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRefreshToken(accessToken, publicKey); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("access token error = %v, want ErrInvalidRefreshToken", err)
	}
	if _, err := ValidateRefreshToken(string(make([]byte, maxTokenSize+1)), publicKey); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("oversized token error = %v, want ErrInvalidRefreshToken", err)
	}
}

func TestValidateAccessTokenRequiresExactES256AndIdentity(t *testing.T) {
	t.Parallel()

	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongAlgorithmClaims := commonjwt.Claims{
		Username: "admin",
		ID:       42,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    AccessTokenIssuer,
		},
	}
	wrongAlgorithm, err := jwt.NewWithClaims(
		jwt.SigningMethodES384,
		wrongAlgorithmClaims,
	).SignedString(p384Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAccessToken(wrongAlgorithm, func() (*ecdsa.PublicKey, error) {
		return &p384Key.PublicKey, nil
	}); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("ES384 token error = %v, want ErrInvalidAccessToken", err)
	}

	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range []struct {
		username string
		id       int
	}{
		{username: "", id: 42},
		{username: "admin", id: 0},
	} {
		token, err := commonjwt.GetAccessToken(identity.username, p256Key, identity.id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateAccessToken(token, func() (*ecdsa.PublicKey, error) {
			return &p256Key.PublicKey, nil
		}); !errors.Is(err, ErrInvalidAccessToken) {
			t.Fatalf("identity %+v error = %v, want ErrInvalidAccessToken", identity, err)
		}
	}

	missingTimeClaims := commonjwt.Claims{
		Username: "admin",
		ID:       42,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: AccessTokenIssuer,
		},
	}
	missingTimes, err := jwt.NewWithClaims(
		jwt.SigningMethodES256,
		missingTimeClaims,
	).SignedString(p256Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAccessToken(missingTimes, func() (*ecdsa.PublicKey, error) {
		return &p256Key.PublicKey, nil
	}); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("missing-time token error = %v, want ErrInvalidAccessToken", err)
	}
}

func TestValidateAccessTokenRejectsExpiredAndWrongKeyTokens(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	expired, err := commonjwt.GenerateToken(
		"admin",
		privateKey,
		1,
		AccessTokenIssuer,
		-time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAccessToken(expired, func() (*ecdsa.PublicKey, error) {
		return &privateKey.PublicKey, nil
	}); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("expired token error = %v, want ErrInvalidAccessToken", err)
	}

	accessToken, err := commonjwt.GetAccessToken("admin", privateKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAccessToken(accessToken, func() (*ecdsa.PublicKey, error) {
		return &otherKey.PublicKey, nil
	}); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("wrong-key token error = %v, want ErrInvalidAccessToken", err)
	}
	if _, err := ValidateAccessToken(accessToken, func() (*ecdsa.PublicKey, error) {
		return &ecdsa.PublicKey{Curve: elliptic.P256()}, nil
	}); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("malformed-key token error = %v, want ErrInvalidAccessToken", err)
	}
}
