package route

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/config"
)

func withCORSOrigins(t *testing.T, raw string) {
	t.Helper()
	previous := config.CommonInfo.CORSOrigins
	config.CommonInfo.CORSOrigins = raw
	t.Cleanup(func() { config.CommonInfo.CORSOrigins = previous })
}

// corsProbe issues one request whose handler is irrelevant: the path is
// JWT-protected, so the response is 401 unless CORS middleware already set
// headers. That keeps these tests independent of service state.
func corsProbe(t *testing.T, handler http.Handler, origin string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/v1/users/current", nil)
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestCORSDefaultIsSameOriginOnly(t *testing.T) {
	withCORSOrigins(t, "")
	handler := InitRouter()

	recorder := corsProbe(t, handler, "https://evil.example")
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("default must emit no CORS headers, got %q", got)
	}
}

func TestCORSExactAllowlist(t *testing.T) {
	withCORSOrigins(t, "https://console.example, http://127.0.0.1:8080")
	handler := InitRouter()

	allowed := corsProbe(t, handler, "https://console.example")
	if got := allowed.Header().Get("Access-Control-Allow-Origin"); got != "https://console.example" {
		t.Fatalf("allowlisted origin must be echoed, got %q", got)
	}
	if got := allowed.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("credentials must be allowed for allowlisted origins, got %q", got)
	}

	denied := corsProbe(t, handler, "https://evil.example")
	if got := denied.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("non-allowlisted origin must not receive CORS headers, got %q", got)
	}
}

func TestCORSRejectsWildcardAndMalformed(t *testing.T) {
	for name, raw := range map[string]string{
		"wildcard":         "*",
		"wildcard in list": "https://ok.example,*",
		"empty entry":      "https://ok.example,,https://two.example",
		"no scheme":        "console.example",
		"with path":        "https://console.example/app",
		"with query":       "https://console.example/?a=1",
		"with userinfo":    "https://user:pass@console.example",
	} {
		if _, err := corsAllowlist(raw); err == nil {
			t.Fatalf("%s: %q must be rejected", name, raw)
		}
	}
	origins, err := corsAllowlist("https://console.example/")
	if err != nil || len(origins) != 1 || origins[0] != "https://console.example" {
		t.Fatalf("trailing slash must normalize to exact origin, got %v %v", origins, err)
	}
}

func TestCORSInvalidConfigurationFailsStartup(t *testing.T) {
	withCORSOrigins(t, "*")
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatalf("wildcard configuration must panic at startup, not serve")
		}
		if !strings.Contains(recovered.(string), "CORSOrigins") {
			t.Fatalf("panic must name the configuration key, got %v", recovered)
		}
	}()
	applyConfiguredCORS(echo.New())
}
