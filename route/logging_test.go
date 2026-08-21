package route

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestSafeRequestLoggerOmitsQueryHeadersAndBody(t *testing.T) {
	t.Parallel()

	const secret = "recasaos-log-secret-sentinel"
	var output bytes.Buffer
	e := echo.New()
	e.Use(safeRequestLoggerTo(&output))
	e.POST("/v1/users/:username", func(ctx echo.Context) error {
		return ctx.NoContent(http.StatusUnauthorized)
	})
	request := httptest.NewRequest(
		http.MethodPost,
		"http://device.test/v1/users/"+secret+"?token="+secret,
		strings.NewReader(`{"password":"`+secret+`"}`),
	)
	request.Header.Set(echo.HeaderAuthorization, secret)
	request.Header.Set("Cookie", "session="+secret)
	response := httptest.NewRecorder()
	e.ServeHTTP(response, request)
	if strings.Contains(output.String(), secret) || strings.Contains(output.String(), "token=") {
		t.Fatalf("request secret appeared in log: %q", output.String())
	}
	if !strings.Contains(output.String(), "method=POST") ||
		!strings.Contains(output.String(), "route=/v1/users/:username") ||
		!strings.Contains(output.String(), "status=401") {
		t.Fatalf("safe request metadata missing from log: %q", output.String())
	}
}
