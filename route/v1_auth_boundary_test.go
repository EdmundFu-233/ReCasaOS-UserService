package route

import (
	"net/http"
	"net/http/httptest"
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
