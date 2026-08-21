package route

import (
	"io"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

const safeRequestLogFormat = "time=${time_rfc3339} method=${method} route=${route} status=${status} latency=${latency_human}\n"

// safeRequestLogger deliberately logs the registered route template rather than
// the request URI. Query strings historically carried JWTs and other secrets,
// and must not be copied into stdout, journald, or CI diagnostics even when
// their use for authentication is rejected.
func safeRequestLogger() echo.MiddlewareFunc {
	return safeRequestLoggerTo(os.Stdout)
}

func safeRequestLoggerTo(output io.Writer) echo.MiddlewareFunc {
	return middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: safeRequestLogFormat,
		Output: output,
	})
}
