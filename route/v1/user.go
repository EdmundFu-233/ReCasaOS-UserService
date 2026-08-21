package v1

import (
	"context"
	"crypto/ecdsa"
	json2 "encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/EdmundFu-233/ReCasaOS-UserService/common"
	"github.com/EdmundFu-233/ReCasaOS-UserService/model"
	"github.com/EdmundFu-233/ReCasaOS-UserService/model/system_model"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/authsecurity"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/config"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/userbootstrap"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/utils/file"
	model2 "github.com/EdmundFu-233/ReCasaOS-UserService/service/model"
	"github.com/IceWhaleTech/CasaOS-Common/utils/common_err"
	"github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/labstack/echo/v4"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/EdmundFu-233/ReCasaOS-UserService/service"
)

// @Summary register user
// @Router /user/register/ [post]
func PostUserRegister(ctx echo.Context) error {
	ctx.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	ctx.Response().Header().Set("Pragma", "no-cache")
	return ctx.JSON(http.StatusGone, model.Result{
		Success: http.StatusGone,
		Message: "network registration is disabled; initialize the administrator locally",
	})
}

var limiter = rate.NewLimiter(rate.Every(time.Minute), 5)

const maxLoginRequestBodyBytes = 4 << 10

// @Summary login
// @Produce  application/json
// @Accept application/json
// @Tags user
// @Param user_name query string true "User name"
// @Param pwd  query string true "password"
// @Success 200 {string} string "ok"
// @Router /user/login [post]
func PostUserLogin(ctx echo.Context) error {
	ctx.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	ctx.Response().Header().Set("Pragma", "no-cache")
	if !limiter.Allow() {
		return ctx.JSON(common_err.TOO_MANY_REQUEST,
			model.Result{
				Success: common_err.TOO_MANY_LOGIN_REQUESTS,
				Message: common_err.GetMsg(common_err.TOO_MANY_LOGIN_REQUESTS),
			})
	}

	requestBody := http.MaxBytesReader(ctx.Response(), ctx.Request().Body, maxLoginRequestBodyBytes)
	decoder := json2.NewDecoder(requestBody)
	decoder.DisallowUnknownFields()
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decoder.Decode(&request); err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.CLIENT_ERROR, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ctx.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.CLIENT_ERROR, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}

	username := request.Username
	password := request.Password
	// check params is empty
	if len(username) == 0 || len(password) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR,
			model.Result{
				Success: common_err.CLIENT_ERROR,
				Message: common_err.GetMsg(common_err.INVALID_PARAMS),
			})
	}
	user, err := service.MyService.User().AuthenticateUser(username, []byte(password))
	if errors.Is(err, service.ErrInvalidCredentials) {
		return ctx.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST_OR_PWD_INVALID, Message: common_err.GetMsg(common_err.USER_NOT_EXIST_OR_PWD_INVALID)})
	}
	if err != nil {
		logger.Error("authenticate user", zap.Error(err))
		return ctx.JSON(http.StatusInternalServerError,
			model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}

	privateKey, _ := service.MyService.User().GetKeyPair()
	if privateKey == nil {
		return ctx.JSON(http.StatusInternalServerError,
			model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}

	token := system_model.VerifyInformation{}

	accessToken, err := jwt.GetAccessToken(user.Username, privateKey, user.Id)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError,
			model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	token.AccessToken = accessToken

	refreshToken, err := jwt.GetRefreshToken(user.Username, privateKey, user.Id)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError,
			model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	token.RefreshToken = refreshToken

	token.ExpiresAt = time.Now().Add(3 * time.Hour * time.Duration(1)).Unix()
	data := make(map[string]interface{}, 2)
	user.Password = ""
	data["token"] = token

	// TODO:1 Database fields cannot be external
	data["user"] = user

	return ctx.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    data,
		})
}

// @Summary edit user head
// @Produce  application/json
// @Accept multipart/form-data
// @Tags user
// @Param file formData file true "用户头像"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /users/avatar [put]
func PutUserAvatar(ctx echo.Context) error {
	return legacyImageEndpointGone(ctx)
}

// @Summary get user head
// @Produce  application/json
// @Tags user
// @Param file formData file true "用户头像"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /users/avatar [get]
func GetUserAvatar(ctx echo.Context) error {
	return legacyImageEndpointGone(ctx)
}

// @Summary edit user name
// @Produce  application/json
// @Accept application/json
// @Tags user
// @Param old_name  query string true "Old user name"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /user/name/:id [put]
func PutUserInfo(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	requested := userProfileUpdate{}
	if err := ctx.Bind(&requested); err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST_OR_PWD_INVALID, Message: common_err.GetMsg(common_err.USER_NOT_EXIST_OR_PWD_INVALID)})
	}
	if len(requested.Username) > 0 {
		u := service.MyService.User().GetUserInfoByUserName(requested.Username)
		if u.Id > 0 && u.Id != user.Id {
			return ctx.JSON(common_err.CLIENT_ERROR,
				model.Result{Success: common_err.USER_EXIST, Message: common_err.GetMsg(common_err.USER_EXIST)})
		}
	}

	updated := model2.UserDBModel{
		Id:          user.Id,
		Username:    firstNonEmpty(requested.Username, user.Username),
		Role:        user.Role,
		Email:       firstNonEmpty(requested.Email, user.Email),
		Nickname:    firstNonEmpty(requested.Nickname, user.Nickname),
		Avatar:      firstNonEmpty(requested.Avatar, user.Avatar),
		Description: firstNonEmpty(requested.Description, user.Description),
	}
	service.MyService.User().UpdateUser(updated)
	publicUser := service.MyService.User().GetUserInfoById(id)
	if publicUser.Id != user.Id {
		return ctx.JSON(http.StatusInternalServerError,
			model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	publicUser.Password = ""
	return ctx.JSON(common_err.SUCCESS, model.Result{
		Success: common_err.SUCCESS,
		Message: common_err.GetMsg(common_err.SUCCESS),
		Data:    publicUser,
	})
}

type userProfileUpdate struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	Nickname    string `json:"nickname"`
	Avatar      string `json:"avatar"`
	Description string `json:"description"`
}

func firstNonEmpty(candidate, fallback string) string {
	if candidate != "" {
		return candidate
	}
	return fallback
}

// @Summary edit user password
// @Produce  application/json
// @Accept application/json
// @Tags user
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /user/password/:id [put]
func PutUserPassword(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	json := make(map[string]string)
	ctx.Bind(&json)
	oldPwd := json["old_password"]
	pwd := json["password"]
	if len(oldPwd) == 0 || len(pwd) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	err := service.MyService.User().ChangeUserPassword(id, []byte(oldPwd), []byte(pwd))
	if errors.Is(err, service.ErrInvalidCredentials) {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.PWD_INVALID_OLD, Message: common_err.GetMsg(common_err.PWD_INVALID_OLD)})
	}
	if errors.Is(err, service.ErrWeakPassword) {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.PWD_IS_TOO_SIMPLE, Message: common_err.GetMsg(common_err.PWD_IS_TOO_SIMPLE)})
	}
	if err != nil {
		logger.Error("change user password", zap.Error(err))
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	user := service.MyService.User().GetUserInfoById(id)
	user.Password = ""
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: user})
}

// @Summary edit user nick
// @Produce  application/json
// @Accept application/json
// @Tags user
// @Param nick_name query string false "nick name"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /user/nick [put]
func PutUserNick(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	json := make(map[string]string)
	ctx.Bind(&json)
	Nickname := json["nick_name"]
	if len(Nickname) == 0 {
		return ctx.JSON(http.StatusOK, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(http.StatusOK,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	user.Nickname = Nickname
	service.MyService.User().UpdateUser(user)
	return ctx.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: user})
}

// @Summary edit user description
// @Produce  application/json
// @Accept multipart/form-data
// @Tags user
// @Param description formData string false "Description"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /user/desc [put]
func PutUserDesc(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	json := make(map[string]string)
	ctx.Bind(&json)
	desc := json["description"]
	if len(desc) == 0 {
		return ctx.JSON(http.StatusOK, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(http.StatusOK,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	user.Description = desc

	service.MyService.User().UpdateUser(user)

	return ctx.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: user})
}

// @Summary get user info
// @Produce  application/json
// @Accept  application/json
// @Tags user
// @Success 200 {string} string "ok"
// @Router /user/info/:id [get]
func GetUserInfo(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	user := service.MyService.User().GetUserInfoById(id)

	return ctx.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    user,
		})
}

/**
 * @description:
 * @param {*gin.Context} c
 * @param {string} Username
 * @return {*}
 * @method:
 * @router:
 */
func GetUserInfoByUsername(ctx echo.Context) error {
	username := ctx.Param("username")
	if len(username) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	user := service.MyService.User().GetUserInfoByUserName(username)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}

	return ctx.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    user,
		})
}

/**
 * @description: get all Usernames
 * @method:GET
 * @router:/user/all/name
 */
func GetUserAllUsername(ctx echo.Context) error {
	users := service.MyService.User().GetAllUserName()
	names := []string{}
	for _, v := range users {
		names = append(names, v.Username)
	}
	return ctx.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    names,
		})
}

/**
 * @description:get custom file by user
 * @param {path} name string "file name"
 * @method: GET
 * @router: /user/custom/:key
 */
func GetUserCustomConf(ctx echo.Context) error {
	name := ctx.Param("key")
	if len(name) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	id := ctx.Request().Header.Get("user_id")

	user := service.MyService.User().GetUserInfoById(id)
	//	user := service.MyService.User().GetUserInfoByUsername(Username)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	filePath := config.AppInfo.UserDataPath + "/" + id + "/" + name + ".json"

	data := file.ReadFullFile(filePath)
	if !gjson.ValidBytes(data) {
		return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: string(data)})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: json2.RawMessage(string(data))})
}

/**
 * @description:create or update custom conf by user
 * @param {path} name string "file name"
 * @method:POST
 * @router:/user/custom/:key
 */
func PostUserCustomConf(ctx echo.Context) error {
	name := ctx.Param("key")
	if len(name) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	id := ctx.Request().Header.Get("user_id")
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	data, _ := io.ReadAll(ctx.Request().Body)
	filePath := config.AppInfo.UserDataPath + "/" + strconv.Itoa(user.Id)

	if err := file.IsNotExistMkDir(filePath); err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}

	if err := file.WriteToPath(data, filePath, name+".json"); err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}

	if name == "system" {
		dataMap := make(map[string]string, 1)
		dataMap["system"] = string(data)
		response, err := service.MyService.MessageBus().PublishEventWithResponse(context.Background(), common.SERVICENAME, "zimaos:user:save_config", dataMap)
		if err != nil {
			logger.Error("failed to publish user configuration event",
				zap.String("event", "zimaos:user:save_config"),
				zap.Error(err))
		} else if response == nil {
			logger.Error("user configuration event returned no response",
				zap.String("event", "zimaos:user:save_config"))
		} else if response.StatusCode() != http.StatusOK {
			logger.Error("user configuration event returned a non-success status",
				zap.String("event", "zimaos:user:save_config"),
				zap.Int("status", response.StatusCode()))
		}

	}

	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: json2.RawMessage(string(data))})
}

/**
 * @description: delete user custom config
 * @param {path} key string
 * @method:delete
 * @router:/user/custom/:key
 */
func DeleteUserCustomConf(ctx echo.Context) error {
	name := ctx.Param("key")
	if len(name) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	id := ctx.Request().Header.Get("user_id")
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	filePath := config.AppInfo.UserDataPath + "/" + strconv.Itoa(user.Id) + "/" + name + ".json"
	err := os.Remove(filePath)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

/**
 * @description:
 * @param {path} id string "user id"
 * @method:DELETE
 * @router:/user/delete/:id
 */
func DeleteUser(ctx echo.Context) error {
	id := ctx.Param("id")
	err := service.MyService.User().DeleteUserById(id)
	if errors.Is(err, service.ErrLastAdmin) {
		return ctx.JSON(http.StatusConflict, model.Result{Success: http.StatusConflict, Message: "at least one administrator must remain"})
	}
	if errors.Is(err, service.ErrUserNotFound) {
		return ctx.JSON(http.StatusNotFound, model.Result{Success: http.StatusNotFound, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	if err != nil {
		logger.Error("delete user", zap.Error(err))
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: id})
}

/**
 * @description:update user image
 * @method:POST
 * @router:/user/current/image/:key
 */
func PutUserImage(ctx echo.Context) error {
	return legacyImageEndpointGone(ctx)
}

/**
* @description:
* @param {*gin.Context} c
* @param {file} file
* @param {string} key
* @param {string} type:avatar,background
* @return {*}
* @method:
* @router:
 */
func PostUserUploadImage(ctx echo.Context) error {
	return legacyImageEndpointGone(ctx)
}

/**
 * @description: get current user's image
 * @method:GET
 * @router:/user/image/:id
 */
func GetUserImage(ctx echo.Context) error {
	return legacyImageEndpointGone(ctx)
}

func DeleteUserImage(ctx echo.Context) error {
	return legacyImageEndpointGone(ctx)
}

func legacyImageEndpointGone(ctx echo.Context) error {
	ctx.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	ctx.Response().Header().Set("Pragma", "no-cache")
	ctx.Response().Header().Set(echo.HeaderXContentTypeOptions, "nosniff")
	return ctx.JSON(http.StatusGone, model.Result{
		Success: http.StatusGone,
		Message: "legacy path-based image endpoints are disabled",
	})
}

/**
 * @description:
 * @param {*gin.Context} c
 * @param {string} refresh_token
 * @return {*}
 * @method:
 * @router:
 */
func PostUserRefreshToken(ctx echo.Context) error {
	ctx.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	ctx.Response().Header().Set("Pragma", "no-cache")

	requestBody := http.MaxBytesReader(ctx.Response(), ctx.Request().Body, maxRefreshRequestBodyBytes)
	decoder := json2.NewDecoder(requestBody)
	decoder.DisallowUnknownFields()
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decoder.Decode(&request); err != nil {
		return refreshUnauthorized(ctx)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return refreshUnauthorized(ctx)
	}

	verifyInfo, err := issueRefreshedTokens(request.RefreshToken, service.MyService.User())
	if errors.Is(err, errInvalidRefreshSession) {
		return refreshUnauthorized(ctx)
	}
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{
			Success: common_err.SERVICE_ERROR,
			Message: common_err.GetMsg(common_err.SERVICE_ERROR),
		})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{
		Success: common_err.SUCCESS,
		Message: common_err.GetMsg(common_err.SUCCESS),
		Data:    verifyInfo,
	})
}

const maxRefreshRequestBodyBytes = 12 << 10

var (
	errInvalidRefreshSession = errors.New("invalid refresh session")
	errRefreshSigning        = errors.New("refresh token signing failed")
)

type refreshTokenUserService interface {
	GetKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey)
	GetUserInfoById(string) model2.UserDBModel
}

func issueRefreshedTokens(refresh string, users refreshTokenUserService) (system_model.VerifyInformation, error) {
	if users == nil {
		return system_model.VerifyInformation{}, errRefreshSigning
	}
	privateKey, publicKey := users.GetKeyPair()
	if privateKey == nil || publicKey == nil {
		return system_model.VerifyInformation{}, errRefreshSigning
	}
	claims, err := authsecurity.ValidateRefreshToken(refresh, func() (*ecdsa.PublicKey, error) {
		return publicKey, nil
	})
	if err != nil {
		return system_model.VerifyInformation{}, errInvalidRefreshSession
	}
	user := users.GetUserInfoById(strconv.Itoa(claims.ID))
	if user.Id != claims.ID || user.Username != claims.Username {
		return system_model.VerifyInformation{}, errInvalidRefreshSession
	}

	newAccessToken, err := jwt.GetAccessToken(user.Username, privateKey, user.Id)
	if err != nil {
		return system_model.VerifyInformation{}, errRefreshSigning
	}
	newRefreshToken, err := jwt.GetRefreshToken(user.Username, privateKey, user.Id)
	if err != nil {
		return system_model.VerifyInformation{}, errRefreshSigning
	}
	return system_model.VerifyInformation{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    time.Now().Add(3 * time.Hour).Unix(),
	}, nil
}

func refreshUnauthorized(ctx echo.Context) error {
	return ctx.JSON(http.StatusUnauthorized, model.Result{
		Success: common_err.VERIFICATION_FAILURE,
		Message: common_err.GetMsg(common_err.VERIFICATION_FAILURE),
	})
}

func DeleteUserAll(ctx echo.Context) error {
	_ = service.MyService.User().DeleteAllUser()
	return ctx.JSON(http.StatusConflict, model.Result{Success: http.StatusConflict, Message: "bulk user deletion is disabled"})
}

// @Summary 检查是否进入引导状态
// @Produce  application/json
// @Accept application/json
// @Tags sys
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /sys/init/check [get]
func GetUserStatus(ctx echo.Context) error {
	return getUserStatus(ctx, service.MyService.User())
}

type initializationStateReader interface {
	GetInitializationState(context.Context) (userbootstrap.State, error)
}

func getUserStatus(ctx echo.Context, reader initializationStateReader) error {
	ctx.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	ctx.Response().Header().Set("Pragma", "no-cache")
	state, err := reader.GetInitializationState(ctx.Request().Context())
	if err != nil {
		return ctx.JSON(http.StatusServiceUnavailable,
			model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	data := map[string]bool{
		"initialized": state.Initialized(),
	}
	return ctx.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    data,
		})
}
