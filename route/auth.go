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
	maxAuthorizationHeaderBytes = 8 << 10
)

var errInvalidAuthorizationHeader = errors.New("invalid authorization header")

// accessSessionValidator is the narrow session surface the authentication
// middleware requires: credential-generation agreement plus access-token
// revocation. Both checks consult the database, so a deleted user, a
// password change, or an explicit logout takes effect without waiting for
// the access token to expire.
type accessSessionValidator interface {
	GetUserTokenVersion(userID int) (string, int, bool)
	IsAccessTokenRevoked(tokenID string) (bool, error)
}

func userAccessTokenMiddleware() echo.MiddlewareFunc {
	return accessTokenMiddleware(func() (*ecdsa.PublicKey, error) {
		if service.MyService == nil {
			return nil, errors.New("user service is unavailable")
		}
		_, publicKey := service.MyService.User().GetKeyPair()
		return publicKey, nil
	}, userSessionValidator())
}

// userSessionValidator exposes the credential store to the middleware, or
// nil when the service is unavailable so every request fails closed.
func userSessionValidator() accessSessionValidator {
	if service.MyService == nil {
		return nil
	}
	return service.MyService.User()
}

func accessTokenMiddleware(
	publicKey func() (*ecdsa.PublicKey, error),
	sessions accessSessionValidator,
) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			token, err := authorizationToken(ctx.Request())
			if err != nil {
				return echo.ErrUnauthorized
			}
			claims, err := authsecurity.ValidateSessionAccessToken(token, publicKey)
			if err != nil {
				return echo.ErrUnauthorized
			}
			if sessions == nil {
				return echo.ErrUnauthorized
			}
			username, version, exists := sessions.GetUserTokenVersion(claims.UserID)
			if !exists || username != claims.Username || version != claims.TokenVersion {
				return echo.ErrUnauthorized
			}
			revoked, err := sessions.IsAccessTokenRevoked(claims.ID)
			if err != nil || revoked {
				return echo.ErrUnauthorized
			}

			ctx.Set(service.SessionContextKey, service.AuthenticatedSession{
				Request:  ctx.Request(),
				UserID:   claims.UserID,
				Username: claims.Username,
				TokenID:  claims.ID,
				Expires:  claims.ExpiresAt.Time,
			})

			// Existing v1 handlers consume this internal value from the request
			// header. It is overwritten only after authentication and never read
			// as client-supplied evidence. A later API cleanup will move those
			// handlers to the typed context value above.
			ctx.Request().Header.Set("user_id", strconv.Itoa(claims.UserID))
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
