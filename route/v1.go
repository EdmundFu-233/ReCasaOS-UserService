package route

import (
	"net/http"

	v1 "github.com/IceWhaleTech/CasaOS-UserService/route/v1"
	"github.com/labstack/echo/v4"
	echo_middleware "github.com/labstack/echo/v4/middleware"
)

func InitRouter() http.Handler {
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

	e.POST("/v1/users/register", v1.PostUserRegister)
	e.POST("/v1/users/login", v1.PostUserLogin)
	e.POST("/v1/users/refresh", v1.PostUserRefreshToken)
	// No short-term modifications
	e.GET("/v1/users/image", v1.GetUserImage)

	e.GET("/v1/users/status", v1.GetUserStatus) // init/check

	v1Group := e.Group("/v1")

	v1UsersGroup := v1Group.Group("/users")
	v1UsersGroup.Use(userAccessTokenMiddleware())
	{
		v1UsersGroup.Use()
		v1UsersGroup.GET("/current", v1.GetUserInfo)
		v1UsersGroup.PUT("/current", v1.PutUserInfo)
		v1UsersGroup.PUT("/current/password", v1.PutUserPassword)

		v1UsersGroup.GET("/current/custom/:key", v1.GetUserCustomConf)
		v1UsersGroup.POST("/current/custom/:key", v1.PostUserCustomConf)
		v1UsersGroup.DELETE("/current/custom/:key", v1.DeleteUserCustomConf)

		v1UsersGroup.POST("/current/image/:key", v1.PostUserUploadImage)
		v1UsersGroup.PUT("/current/image/:key", v1.PutUserImage)
		// v1UserGroup.POST("/file/image/:key", v1.PostUserFileImage)
		v1UsersGroup.DELETE("/current/image", v1.DeleteUserImage)

		v1UsersGroup.PUT("/avatar", v1.PutUserAvatar)
		v1UsersGroup.GET("/avatar", v1.GetUserAvatar)
		v1UsersGroup.GET("/name", v1.GetUserAllUsername)

		v1UsersGroup.DELETE("/:id", v1.DeleteUser)
		v1UsersGroup.GET("/:username", v1.GetUserInfoByUsername)
		v1UsersGroup.DELETE("", v1.DeleteUserAll)
	}

	return e
}
