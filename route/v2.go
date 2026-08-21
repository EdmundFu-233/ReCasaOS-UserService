package route

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	codegen "github.com/IceWhaleTech/CasaOS-UserService/codegen/user_service"
	v2 "github.com/IceWhaleTech/CasaOS-UserService/route/v2"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/labstack/echo/v4"
	echo_middleware "github.com/labstack/echo/v4/middleware"
	echomiddleware "github.com/oapi-codegen/echo-middleware"
)

var (
	_swagger *openapi3.T

	V2APIPath string
	V2DocPath string
)

const v2OpenAPISecuritySchemeName = "access_token"

func init() {
	swagger, err := codegen.GetSwagger()
	if err != nil {
		panic(err)
	}

	_swagger = swagger

	u, err := url.Parse(_swagger.Servers[0].URL)
	if err != nil {
		panic(err)
	}

	V2APIPath = strings.TrimRight(u.Path, "/")
	V2DocPath = "/doc" + V2APIPath
}

func InitV2Router() http.Handler {
	UserService := v2.NewUserService()

	e := echo.New()

	e.Use((echo_middleware.CORSWithConfig(echo_middleware.CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{echo.POST, echo.GET, echo.OPTIONS, echo.PUT, echo.DELETE},
		AllowHeaders:     []string{echo.HeaderAuthorization, echo.HeaderContentLength, echo.HeaderXCSRFToken, echo.HeaderContentType, echo.HeaderAccessControlAllowOrigin, echo.HeaderAccessControlAllowHeaders, echo.HeaderAccessControlAllowMethods, echo.HeaderConnection, echo.HeaderOrigin, echo.HeaderXRequestedWith},
		ExposeHeaders:    []string{echo.HeaderContentLength, echo.HeaderAccessControlAllowOrigin, echo.HeaderAccessControlAllowHeaders},
		MaxAge:           172800,
		AllowCredentials: true,
	})))

	e.Use(echo_middleware.Gzip())

	e.Use(safeRequestLogger())

	e.Use(userAccessTokenMiddleware())

	e.Use(echomiddleware.OapiRequestValidatorWithOptions(
		_swagger,
		&echomiddleware.Options{Options: openapi3filter.Options{
			AuthenticationFunc: v2OpenAPIAuthentication,
		}},
	))

	codegen.RegisterHandlersWithBaseURL(e, UserService, V2APIPath)

	return e
}

func v2OpenAPIAuthentication(
	ctx context.Context,
	input *openapi3filter.AuthenticationInput,
) error {
	if input == nil ||
		input.RequestValidationInput == nil ||
		input.RequestValidationInput.Request == nil ||
		input.SecuritySchemeName != v2OpenAPISecuritySchemeName ||
		input.SecurityScheme == nil ||
		input.SecurityScheme.Type != "apiKey" ||
		input.SecurityScheme.In != "header" ||
		input.SecurityScheme.Name != echo.HeaderAuthorization ||
		len(input.Scopes) != 0 {
		return echo.ErrUnauthorized
	}

	echoContext := echomiddleware.GetEchoContext(ctx)
	if echoContext == nil || echoContext.Request() == nil ||
		echoContext.Request() != input.RequestValidationInput.Request {
		return echo.ErrUnauthorized
	}
	authentication, ok := echoContext.Get(userAuthenticationContextKey).(userAuthentication)
	if !ok || authentication.request != echoContext.Request() {
		return echo.ErrUnauthorized
	}
	return nil
}

func InitV2DocRouter(docHTML string, docYAML string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == V2DocPath {
			if _, err := w.Write([]byte(docHTML)); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}

		if r.URL.Path == V2DocPath+"/openapi.yaml" {
			if _, err := w.Write([]byte(docYAML)); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	})
}
