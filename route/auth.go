package route

import (
	"crypto/ecdsa"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/authsecurity"
	"github.com/EdmundFu-233/ReCasaOS-UserService/service"
	"github.com/labstack/echo/v4"
)

const (
	userAuthenticationContextKey = "recasaos/user-authentication"
	maxAuthorizationHeaderBytes  = 8 << 10
)

var errInvalidAuthorizationHeader = errors.New("invalid authorization header")

// userAuthentication binds verified claims to the exact request that was
// authenticated. It is intentionally not inferred from source IP or proxy
// headers.
type userAuthentication struct {
	request  *http.Request
	userID   int
	username string
}

func userAccessTokenMiddleware() echo.MiddlewareFunc {
	return accessTokenMiddleware(func() (*ecdsa.PublicKey, error) {
		_, publicKey := service.MyService.User().GetKeyPair()
		return publicKey, nil
	})
}

func accessTokenMiddleware(
	publicKey func() (*ecdsa.PublicKey, error),
) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			token, err := authorizationToken(ctx.Request())
			if err != nil {
				return echo.ErrUnauthorized
			}
			claims, err := authsecurity.ValidateAccessToken(token, publicKey)
			if err != nil {
				return echo.ErrUnauthorized
			}

			ctx.Set(userAuthenticationContextKey, userAuthentication{
				request:  ctx.Request(),
				userID:   claims.ID,
				username: claims.Username,
			})

			// Existing v1 handlers consume this internal value from the request
			// header. It is overwritten only after authentication and never read
			// as client-supplied evidence. A later API cleanup will move those
			// handlers to the typed context value above.
			ctx.Request().Header.Set("user_id", strconv.Itoa(claims.ID))
			return next(ctx)
		}
	}
}

func authorizationToken(request *http.Request) (string, error) {
	if request == nil {
		return "", errInvalidAuthorizationHeader
	}
	values := request.Header.Values(echo.HeaderAuthorization)
	if len(values) != 1 {
		return "", errInvalidAuthorizationHeader
	}
	raw := values[0]
	if len(raw) == 0 || len(raw) > maxAuthorizationHeaderBytes ||
		strings.TrimSpace(raw) != raw ||
		strings.ContainsAny(raw, ",\r\n\x00") {
		return "", errInvalidAuthorizationHeader
	}

	// Current CasaOS UI releases send the compact JWT directly. Accept that
	// exact legacy header shape during the UI migration, while also accepting
	// the canonical Bearer scheme. Query, cookie and form tokens are never
	// inspected. Once the pinned UI has migrated, the raw form can be removed.
	token := raw
	if len(raw) >= len("Bearer") && strings.EqualFold(raw[:len("Bearer")], "Bearer") {
		if len(raw) <= len("Bearer ") || raw[len("Bearer")] != ' ' {
			return "", errInvalidAuthorizationHeader
		}
		token = raw[len("Bearer "):]
	}
	if token == "" || len(token) > maxAuthorizationHeaderBytes ||
		strings.Count(token, ".") != 2 || strings.ContainsAny(token, " \t") {
		return "", errInvalidAuthorizationHeader
	}
	for _, character := range token {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return "", errInvalidAuthorizationHeader
	}
	return token, nil
}
