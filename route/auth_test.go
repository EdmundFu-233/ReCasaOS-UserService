package route

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/authsecurity"
	"github.com/EdmundFu-233/ReCasaOS-UserService/service"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
)

type fakeAccessSessionStore struct {
	username string
	userID   int
	version  int
	exists   bool
	revoked  map[string]bool
}

func (fake *fakeAccessSessionStore) GetUserTokenVersion(userID int) (string, int, bool) {
	if fake == nil || !fake.exists || userID != fake.userID {
		return "", 0, false
	}
	return fake.username, fake.version, true
}

func (fake *fakeAccessSessionStore) IsAccessTokenRevoked(tokenID string) bool {
	if fake == nil {
		return false
	}
	return fake.revoked[tokenID]
}

func validAccessSessionStore() *fakeAccessSessionStore {
	return &fakeAccessSessionStore{username: "admin", userID: 17, version: 0, exists: true, revoked: map[string]bool{}}
}

func mustSessionAccessToken(t *testing.T, privateKey *ecdsa.PrivateKey, username string, userID, version int, tokenID string) string {
	t.Helper()
	token, err := authsecurity.MintAccessToken(username, userID, version, tokenID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestAccessTokenMiddlewareRejectsLocalityAndNonHeaderTokens(t *testing.T) {
	t.Parallel()

	privateKey := mustTestAuthenticationKey(t)
	accessToken := mustSessionAccessToken(t, privateKey, "admin", 17, 0, "query-token-jti")

	tests := []struct {
		name      string
		configure func(*http.Request)
	}{
		{name: "loopback without token"},
		{
			name: "forged forwarding headers",
			configure: func(request *http.Request) {
				request.Header.Set("X-Forwarded-For", "127.0.0.1")
				request.Header.Set("X-Real-IP", "::1")
			},
		},
		{
			name: "query token",
			configure: func(request *http.Request) {
				query := request.URL.Query()
				query.Set("token", accessToken)
				request.URL.RawQuery = query.Encode()
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodGet, "http://device.test/private", nil)
			request.RemoteAddr = "127.0.0.1:42000"
			if test.configure != nil {
				test.configure(request)
			}
			response := serveAuthenticatedTestRequest(t, privateKey, validAccessSessionStore(), request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestRoutersWireAuthenticationBeforeProtectedHandlers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler http.Handler
		path    string
	}{
		{name: "v1", handler: InitRouter(), path: "/v1/users/current"},
		{name: "v2", handler: InitV2Router(), path: V2APIPath + "/events"},
		{name: "v2 encoded uppercase slash", handler: InitV2Router(), path: V2APIPath + "/events%2Fextra"},
		{name: "v2 encoded lowercase slash", handler: InitV2Router(), path: V2APIPath + "/events%2fextra"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for _, configure := range []func(*http.Request){
				func(request *http.Request) {},
				func(request *http.Request) {
					request.Header.Set("X-Forwarded-For", "127.0.0.1")
					request.Header.Set("X-Real-IP", "::1")
				},
				func(request *http.Request) {
					query := request.URL.Query()
					query.Set("token", "header.payload.signature")
					request.URL.RawQuery = query.Encode()
				},
			} {
				request := httptest.NewRequest(http.MethodGet, "http://device.test"+test.path, nil)
				request.RemoteAddr = "127.0.0.1:42000"
				configure(request)
				response := httptest.NewRecorder()
				test.handler.ServeHTTP(response, request)
				if response.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
				}
			}
		})
	}
}

func TestAccessTokenMiddlewareAcceptsAccessHeaderOnly(t *testing.T) {
	t.Parallel()

	privateKey := mustTestAuthenticationKey(t)
	accessToken := mustSessionAccessToken(t, privateKey, "admin", 17, 0, "header-shape-jti")
	for _, authorization := range []string{
		accessToken,
		"Bearer " + accessToken,
		"bearer " + accessToken,
		"bEaReR " + accessToken,
	} {
		request := httptest.NewRequest(http.MethodGet, "http://device.test/private", nil)
		request.Header.Set(echo.HeaderAuthorization, authorization)
		response := serveAuthenticatedTestRequest(t, privateKey, validAccessSessionStore(), request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("authorization %q status = %d, want %d", authorization[:8], response.Code, http.StatusNoContent)
		}
	}
}

func TestAccessTokenMiddlewareRejectsRefreshAndMalformedHeaders(t *testing.T) {
	t.Parallel()

	privateKey := mustTestAuthenticationKey(t)
	refreshToken, err := authsecurity.MintRefreshToken("admin", 17, 0, "refresh-jti", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	accessToken := mustSessionAccessToken(t, privateKey, "admin", 17, 0, "malformed-jti")
	tests := []func(*http.Request){
		func(request *http.Request) { request.Header.Set(echo.HeaderAuthorization, refreshToken) },
		func(request *http.Request) { request.Header.Set(echo.HeaderAuthorization, "Bearer") },
		func(request *http.Request) { request.Header.Set(echo.HeaderAuthorization, "Bearer\t"+accessToken) },
		func(request *http.Request) {
			request.Header.Set(echo.HeaderAuthorization, accessToken+","+accessToken)
		},
		func(request *http.Request) {
			request.Header.Add(echo.HeaderAuthorization, accessToken)
			request.Header.Add(echo.HeaderAuthorization, accessToken)
		},
		func(request *http.Request) {
			request.Header.Set(echo.HeaderAuthorization, strings.Repeat("a", maxAuthorizationHeaderBytes+1))
		},
	}
	for index, configure := range tests {
		request := httptest.NewRequest(http.MethodGet, "http://device.test/private", nil)
		configure(request)
		response := serveAuthenticatedTestRequest(t, privateKey, validAccessSessionStore(), request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("test %d status = %d, want %d", index, response.Code, http.StatusUnauthorized)
		}
	}
}

func TestAccessTokenMiddlewareRejectsExpiredAndWrongKey(t *testing.T) {
	t.Parallel()

	privateKey := mustTestAuthenticationKey(t)
	otherKey := mustTestAuthenticationKey(t)
	expired := mustExpiredSessionToken(t, privateKey)
	valid := mustSessionAccessToken(t, privateKey, "admin", 17, 0, "valid-jti")
	for _, test := range []struct {
		token string
		key   *ecdsa.PrivateKey
	}{
		{token: expired, key: privateKey},
		{token: valid, key: otherKey},
	} {
		request := httptest.NewRequest(http.MethodGet, "http://device.test/private", nil)
		request.Header.Set(echo.HeaderAuthorization, test.token)
		response := serveAuthenticatedTestRequest(t, test.key, validAccessSessionStore(), request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
		}
	}
}

func mustExpiredSessionToken(t *testing.T, privateKey *ecdsa.PrivateKey) string {
	t.Helper()
	past := time.Now().Add(-time.Hour)
	claims := authsecurity.SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "casaos",
			Subject:   "admin",
			ID:        "expired-jti",
			IssuedAt:  jwt.NewNumericDate(past),
			NotBefore: jwt.NewNumericDate(past),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
		Username:     "admin",
		UserID:       17,
		TokenVersion: 0,
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestAccessTokenMiddlewareRejectsRevokedVersionAndUnknownUser(t *testing.T) {
	t.Parallel()

	privateKey := mustTestAuthenticationKey(t)
	oldVersion := mustSessionAccessToken(t, privateKey, "admin", 17, 0, "version-jti")
	revoked := mustSessionAccessToken(t, privateKey, "admin", 17, 1, "revoked-jti")
	renamed := mustSessionAccessToken(t, privateKey, "renamed", 17, 1, "renamed-jti")

	store := &fakeAccessSessionStore{username: "admin", userID: 17, version: 1, exists: true, revoked: map[string]bool{"revoked-jti": true}}
	for _, test := range []struct {
		name  string
		token string
	}{
		{name: "stale version", token: oldVersion},
		{name: "revoked identifier", token: revoked},
		{name: "renamed user", token: renamed},
	} {
		request := httptest.NewRequest(http.MethodGet, "http://device.test/private", nil)
		request.Header.Set(echo.HeaderAuthorization, test.token)
		response := serveAuthenticatedTestRequest(t, privateKey, store, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s status = %d, want %d", test.name, response.Code, http.StatusUnauthorized)
		}
	}

	unknown := &fakeAccessSessionStore{username: "admin", userID: 17, version: 0, exists: false, revoked: map[string]bool{}}
	request := httptest.NewRequest(http.MethodGet, "http://device.test/private", nil)
	request.Header.Set(echo.HeaderAuthorization, mustSessionAccessToken(t, privateKey, "admin", 17, 0, "deleted-jti"))
	if response := serveAuthenticatedTestRequest(t, privateKey, unknown, request); response.Code != http.StatusUnauthorized {
		t.Fatalf("deleted user status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestAccessTokenMiddlewareFailsClosedWithoutSessionStore(t *testing.T) {
	t.Parallel()

	privateKey := mustTestAuthenticationKey(t)
	accessToken := mustSessionAccessToken(t, privateKey, "admin", 17, 0, "no-store-jti")
	request := httptest.NewRequest(http.MethodGet, "http://device.test/private", nil)
	request.Header.Set(echo.HeaderAuthorization, accessToken)
	response := serveAuthenticatedTestRequest(t, privateKey, nil, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func serveAuthenticatedTestRequest(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	store *fakeAccessSessionStore,
	request *http.Request,
) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	e.Use(accessTokenMiddleware(func() (*ecdsa.PublicKey, error) {
		return &privateKey.PublicKey, nil
	}, store))
	e.GET("/private", func(ctx echo.Context) error {
		authentication, ok := ctx.Get(service.SessionContextKey).(service.AuthenticatedSession)
		if !ok || authentication.Request != ctx.Request() ||
			authentication.UserID != 17 || authentication.Username != "admin" ||
			authentication.TokenID == "" ||
			ctx.Request().Header.Get("user_id") != "17" {
			return echo.ErrUnauthorized
		}
		return ctx.NoContent(http.StatusNoContent)
	})
	response := httptest.NewRecorder()
	e.ServeHTTP(response, request)
	return response
}

func mustTestAuthenticationKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
