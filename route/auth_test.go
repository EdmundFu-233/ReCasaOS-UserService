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

	commonjwt "github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"github.com/labstack/echo/v4"
)

func TestAccessTokenMiddlewareRejectsLocalityAndNonHeaderTokens(t *testing.T) {
	t.Parallel()

	privateKey := mustTestAuthenticationKey(t)
	accessToken, err := commonjwt.GetAccessToken("admin", privateKey, 17)
	if err != nil {
		t.Fatal(err)
	}

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
			response := serveAuthenticatedTestRequest(t, privateKey, request)
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
	accessToken, err := commonjwt.GetAccessToken("admin", privateKey, 17)
	if err != nil {
		t.Fatal(err)
	}
	for _, authorization := range []string{
		accessToken,
		"Bearer " + accessToken,
		"bearer " + accessToken,
		"bEaReR " + accessToken,
	} {
		request := httptest.NewRequest(http.MethodGet, "http://device.test/private", nil)
		request.Header.Set(echo.HeaderAuthorization, authorization)
		response := serveAuthenticatedTestRequest(t, privateKey, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("authorization %q status = %d, want %d", authorization[:8], response.Code, http.StatusNoContent)
		}
	}
}

func TestAccessTokenMiddlewareRejectsRefreshAndMalformedHeaders(t *testing.T) {
	t.Parallel()

	privateKey := mustTestAuthenticationKey(t)
	refreshToken, err := commonjwt.GetRefreshToken("admin", privateKey, 17)
	if err != nil {
		t.Fatal(err)
	}
	accessToken, err := commonjwt.GetAccessToken("admin", privateKey, 17)
	if err != nil {
		t.Fatal(err)
	}
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
		response := serveAuthenticatedTestRequest(t, privateKey, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("test %d status = %d, want %d", index, response.Code, http.StatusUnauthorized)
		}
	}
}

func TestAccessTokenMiddlewareRejectsExpiredAndWrongKey(t *testing.T) {
	t.Parallel()

	privateKey := mustTestAuthenticationKey(t)
	otherKey := mustTestAuthenticationKey(t)
	expired, err := commonjwt.GenerateToken("admin", privateKey, 17, "casaos", -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := commonjwt.GetAccessToken("admin", privateKey, 17)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		token string
		key   *ecdsa.PrivateKey
	}{
		{token: expired, key: privateKey},
		{token: valid, key: otherKey},
	} {
		request := httptest.NewRequest(http.MethodGet, "http://device.test/private", nil)
		request.Header.Set(echo.HeaderAuthorization, test.token)
		response := serveAuthenticatedTestRequest(t, test.key, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
		}
	}
}

func serveAuthenticatedTestRequest(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	request *http.Request,
) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	e.Use(accessTokenMiddleware(func() (*ecdsa.PublicKey, error) {
		return &privateKey.PublicKey, nil
	}))
	e.GET("/private", func(ctx echo.Context) error {
		authentication, ok := ctx.Get(userAuthenticationContextKey).(userAuthentication)
		if !ok || authentication.request != ctx.Request() ||
			authentication.userID != 17 || authentication.username != "admin" ||
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
