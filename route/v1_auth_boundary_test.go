package route

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUsernameListCannotBypassJWTWithLoopbackForwardingOrQueryToken(t *testing.T) {
	handler := InitRouter()
	tests := []struct {
		name   string
		target string
		xff    string
	}{
		{name: "ordinary unauthenticated request", target: "/v1/users/name"},
		{name: "spoofed loopback forwarding", target: "/v1/users/name", xff: "127.0.0.1"},
		{name: "query token is ignored", target: "/v1/users/name?token=must-not-be-accepted"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			request.RemoteAddr = "203.0.113.10:43210"
			if test.xff != "" {
				request.Header.Set("X-Forwarded-For", test.xff)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestLegacyPublicImagePathEndpointIsGone(t *testing.T) {
	handler := InitRouter()
	const secretPath = "/var/lib/casaos/1/system.json"
	request := httptest.NewRequest(
		http.MethodGet,
		"/v1/users/image?path="+secretPath+"&token=must-not-be-reflected",
		nil,
	)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410; body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" ||
		recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers = %#v", recorder.Header())
	}
	for _, forbidden := range []string{secretPath, "system.json", "must-not-be-reflected"} {
		if strings.Contains(recorder.Body.String(), forbidden) {
			t.Fatalf("response reflected %q: %s", forbidden, recorder.Body.String())
		}
	}
}
