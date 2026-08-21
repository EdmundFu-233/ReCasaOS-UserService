package route

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/oapi-codegen/echo-middleware"
)

func TestV2OpenAPIAuthenticationBindsExactVerifiedRequest(t *testing.T) {
	t.Parallel()

	e := echo.New()
	request := httptest.NewRequest(http.MethodGet, "http://device.test/v2/users/events", nil)
	echoContext := e.NewContext(request, httptest.NewRecorder())
	echoContext.Set(userAuthenticationContextKey, userAuthentication{
		request:  request,
		userID:   7,
		username: "admin",
	})
	callbackContext := context.WithValue(
		context.Background(),
		echomiddleware.EchoContextKey,
		echoContext,
	)
	input := validV2AuthenticationInput(request)
	if err := v2OpenAPIAuthentication(callbackContext, input); err != nil {
		t.Fatalf("valid authentication rejected: %v", err)
	}

	otherRequest := request.Clone(request.Context())
	input.RequestValidationInput.Request = otherRequest
	if err := v2OpenAPIAuthentication(callbackContext, input); !errors.Is(err, echo.ErrUnauthorized) {
		t.Fatalf("different request error = %v, want unauthorized", err)
	}
}

func TestV2OpenAPIAuthenticationRejectsMalformedContracts(t *testing.T) {
	t.Parallel()

	e := echo.New()
	request := httptest.NewRequest(http.MethodGet, "http://device.test/v2/users/events", nil)
	echoContext := e.NewContext(request, httptest.NewRecorder())
	callbackContext := context.WithValue(
		context.Background(),
		echomiddleware.EchoContextKey,
		echoContext,
	)

	tests := []struct {
		name   string
		mutate func(*openapi3filter.AuthenticationInput)
	}{
		{name: "missing verification", mutate: func(*openapi3filter.AuthenticationInput) {}},
		{name: "nil input", mutate: nil},
		{name: "wrong scheme name", mutate: func(input *openapi3filter.AuthenticationInput) {
			input.SecuritySchemeName = "refresh_token"
		}},
		{name: "query scheme", mutate: func(input *openapi3filter.AuthenticationInput) {
			input.SecurityScheme.In = "query"
		}},
		{name: "wrong header", mutate: func(input *openapi3filter.AuthenticationInput) {
			input.SecurityScheme.Name = "X-Token"
		}},
		{name: "scopes", mutate: func(input *openapi3filter.AuthenticationInput) {
			input.Scopes = []string{"admin"}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var input *openapi3filter.AuthenticationInput
			if test.mutate != nil {
				input = validV2AuthenticationInput(request)
				test.mutate(input)
			}
			if err := v2OpenAPIAuthentication(callbackContext, input); !errors.Is(err, echo.ErrUnauthorized) {
				t.Fatalf("error = %v, want unauthorized", err)
			}
		})
	}
}

func validV2AuthenticationInput(request *http.Request) *openapi3filter.AuthenticationInput {
	return &openapi3filter.AuthenticationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: request,
		},
		SecuritySchemeName: v2OpenAPISecuritySchemeName,
		SecurityScheme: &openapi3.SecurityScheme{
			Type: "apiKey",
			In:   "header",
			Name: echo.HeaderAuthorization,
		},
	}
}
