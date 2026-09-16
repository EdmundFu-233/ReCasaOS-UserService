package route

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
	echo_middleware "github.com/labstack/echo/v4/middleware"

	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/config"
)

// corsAllowlist parses the operator-configured exact origin list. Empty
// (the default) means same-origin only. A wildcard is rejected outright:
// credentialed CORS with a wildcard is contradictory and was the previous
// behavior.
func corsAllowlist(raw string) ([]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	origins := make([]string, 0, 4)
	for _, part := range strings.Split(trimmed, ",") {
		origin := strings.TrimSpace(part)
		if origin == "" {
			return nil, errors.New("empty CORS origin")
		}
		if origin == "*" {
			return nil, errors.New("wildcard CORS origin is forbidden with credentials")
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed == nil ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") ||
			parsed.Host == "" || parsed.User != nil ||
			parsed.RawQuery != "" || parsed.Fragment != "" ||
			(parsed.Path != "" && parsed.Path != "/") {
			return nil, errors.New("CORS origin must be an exact http(s) origin")
		}
		origins = append(origins, parsed.Scheme+"://"+parsed.Host)
	}
	return origins, nil
}

// applyConfiguredCORS installs the CORS middleware only when the operator
// configured at least one exact origin. Invalid configuration fails startup
// instead of silently degrading to a weaker or broader policy.
func applyConfiguredCORS(e *echo.Echo) {
	origins, err := corsAllowlist(config.CommonInfo.CORSOrigins)
	if err != nil {
		panic(fmt.Sprintf("invalid common.CORSOrigins configuration: %v", err))
	}
	if len(origins) == 0 {
		return
	}
	e.Use(echo_middleware.CORSWithConfig(echo_middleware.CORSConfig{
		AllowOrigins:     origins,
		AllowMethods:     []string{echo.POST, echo.GET, echo.OPTIONS, echo.PUT, echo.DELETE},
		AllowHeaders:     []string{echo.HeaderAuthorization, echo.HeaderContentLength, echo.HeaderXCSRFToken, echo.HeaderContentType, echo.HeaderOrigin, echo.HeaderXRequestedWith},
		ExposeHeaders:    []string{echo.HeaderContentLength},
		MaxAge:           600,
		AllowCredentials: true,
	}))
}
