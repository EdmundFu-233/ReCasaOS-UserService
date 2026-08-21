package v1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/authsecurity"
	"github.com/EdmundFu-233/ReCasaOS-UserService/service"
	model2 "github.com/EdmundFu-233/ReCasaOS-UserService/service/model"
	commonjwt "github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
)

func TestLegacyImageHandlersFailClosedWithoutTouchingPaths(t *testing.T) {
	t.Parallel()

	const secret = "/var/lib/casaos/1/system.json"
	handlers := []struct {
		name   string
		method string
		target string
		body   string
		call   func(echo.Context) error
	}{
		{name: "put avatar", method: http.MethodPut, target: "/v1/users/avatar", body: `{"file":"` + secret + `"}`, call: PutUserAvatar},
		{name: "get avatar", method: http.MethodGet, target: "/v1/users/avatar", call: GetUserAvatar},
		{name: "copy image", method: http.MethodPut, target: "/v1/users/current/image/background", body: `{"path":"` + secret + `"}`, call: PutUserImage},
		{name: "upload image", method: http.MethodPost, target: "/v1/users/current/image/background", body: secret, call: PostUserUploadImage},
		{name: "public image", method: http.MethodGet, target: "/v1/users/image?path=" + secret, call: GetUserImage},
		{name: "delete image", method: http.MethodDelete, target: "/v1/users/current/image?path=" + secret, call: DeleteUserImage},
	}
	for _, test := range handlers {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			e := echo.New()
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			recorder := httptest.NewRecorder()
			if err := test.call(e.NewContext(request, recorder)); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != http.StatusGone {
				t.Fatalf("status = %d, want 410; body=%s", recorder.Code, recorder.Body.String())
			}
			if recorder.Header().Get(echo.HeaderCacheControl) != "no-store" ||
				recorder.Header().Get(echo.HeaderXContentTypeOptions) != "nosniff" {
				t.Fatalf("security headers = %#v", recorder.Header())
			}
			if strings.Contains(recorder.Body.String(), secret) || strings.Contains(recorder.Body.String(), "system.json") {
				t.Fatalf("response reflected secret path: %s", recorder.Body.String())
			}
		})
	}
}

func TestIssueRefreshedTokensRejectsDeletedOrRenamedUsers(t *testing.T) {
	t.Parallel()

	privateKey := mustRefreshKey(t)
	refresh, err := commonjwt.GetRefreshToken("admin", privateKey, 7)
	if err != nil {
		t.Fatal(err)
	}
	validUsers := refreshUserStub{
		privateKey: privateKey,
		user:       model2.UserDBModel{Id: 7, Username: "admin", Role: "admin"},
	}
	issued, err := issueRefreshedTokens(refresh, validUsers)
	if err != nil {
		t.Fatalf("valid refresh failed: %v", err)
	}
	publicKey := func() (*ecdsa.PublicKey, error) { return &privateKey.PublicKey, nil }
	if _, err := authsecurity.ValidateAccessToken(issued.AccessToken, publicKey); err != nil {
		t.Fatalf("issued access token invalid: %v", err)
	}
	if _, err := authsecurity.ValidateRefreshToken(issued.RefreshToken, publicKey); err != nil {
		t.Fatalf("issued refresh token invalid: %v", err)
	}

	for _, users := range []refreshUserStub{
		{privateKey: privateKey},
		{privateKey: privateKey, user: model2.UserDBModel{Id: 7, Username: "renamed", Role: "admin"}},
	} {
		if _, err := issueRefreshedTokens(refresh, users); !errors.Is(err, errInvalidRefreshSession) {
			t.Fatalf("stale refresh error = %v, want errInvalidRefreshSession", err)
		}
	}
	access, err := commonjwt.GetAccessToken("admin", privateKey, 7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issueRefreshedTokens(access, validUsers); !errors.Is(err, errInvalidRefreshSession) {
		t.Fatalf("access-as-refresh error = %v, want errInvalidRefreshSession", err)
	}
}

func TestRefreshHandlerRejectsMalformedBodiesWithoutReflectingSecrets(t *testing.T) {
	t.Parallel()

	const secret = "do-not-reflect-refresh-token"
	for _, body := range []string{
		`{"refresh_token":"` + secret + `","unexpected":"field"}`,
		`{"refresh_token":"` + secret + `"} trailing`,
		`{"refresh_token":"` + strings.Repeat("a", maxRefreshRequestBodyBytes) + `"}`,
	} {
		e := echo.New()
		request := httptest.NewRequest(http.MethodPost, "/v1/users/refresh", strings.NewReader(body))
		request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		recorder := httptest.NewRecorder()
		if err := PostUserRefreshToken(e.NewContext(request, recorder)); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body=%s", recorder.Code, recorder.Body.String())
		}
		if recorder.Header().Get(echo.HeaderCacheControl) != "no-store" ||
			strings.Contains(recorder.Body.String(), secret) {
			t.Fatalf("unsafe refresh response headers/body: %#v %s", recorder.Header(), recorder.Body.String())
		}
	}
}

func TestLoginRejectsMalformedOrOversizedBodiesWithoutReflectingSecrets(t *testing.T) {
	originalLimiter := limiter
	limiter = rate.NewLimiter(rate.Inf, 100)
	t.Cleanup(func() { limiter = originalLimiter })

	const secret = "do-not-reflect-login-password"
	for _, body := range []string{
		`{"username":"admin","password":"` + secret + `","unexpected":"field"}`,
		`{"username":"admin","password":"` + secret + `"} trailing`,
		`{"username":"admin","password":"` + strings.Repeat("a", maxLoginRequestBodyBytes) + `"}`,
	} {
		e := echo.New()
		request := httptest.NewRequest(http.MethodPost, "/v1/users/login", strings.NewReader(body))
		request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		recorder := httptest.NewRecorder()
		if err := PostUserLogin(e.NewContext(request, recorder)); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", recorder.Code, recorder.Body.String())
		}
		if recorder.Header().Get(echo.HeaderCacheControl) != "no-store" ||
			strings.Contains(recorder.Body.String(), secret) {
			t.Fatalf("unsafe login response headers/body: %#v %s", recorder.Header(), recorder.Body.String())
		}
	}
}

func TestPutUserInfoIgnoresIdentityAndPasswordFields(t *testing.T) {
	originalRepository := service.MyService
	t.Cleanup(func() { service.MyService = originalRepository })

	users := &profileUserStub{current: model2.UserDBModel{
		Id:       1,
		Username: "admin",
		Role:     "admin",
		Email:    "old@example.test",
	}}
	service.MyService = profileRepositoryStub{Repository: originalRepository, users: users}

	const secret = "must-not-be-reflected-password"
	body := `{"id":999,"username":"renamed","role":"user","password":"` + secret + `","email":"new@example.test"}`
	e := echo.New()
	request := httptest.NewRequest(http.MethodPut, "/v1/users/current", strings.NewReader(body))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	request.Header.Set("user_id", "1")
	recorder := httptest.NewRecorder()
	if err := PutUserInfo(e.NewContext(request, recorder)); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}
	if users.saved.Id != 1 || users.saved.Role != "admin" || users.saved.Password != "" ||
		users.saved.Username != "renamed" || users.saved.Email != "new@example.test" {
		t.Fatalf("saved user = %#v", users.saved)
	}
	if strings.Contains(recorder.Body.String(), secret) || strings.Contains(recorder.Body.String(), `"id":999`) ||
		strings.Contains(recorder.Body.String(), `"role":"user"`) {
		t.Fatalf("response reflected untrusted identity or secret: %s", recorder.Body.String())
	}
	var response struct {
		Data model2.UserDBModel `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Id != 1 || response.Data.Role != "admin" || response.Data.Password != "" {
		t.Fatalf("response user = %#v", response.Data)
	}
}

type refreshUserStub struct {
	privateKey *ecdsa.PrivateKey
	user       model2.UserDBModel
}

func (stub refreshUserStub) GetKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	if stub.privateKey == nil {
		return nil, nil
	}
	return stub.privateKey, &stub.privateKey.PublicKey
}

func (stub refreshUserStub) GetUserInfoById(id string) model2.UserDBModel {
	if id == strconv.Itoa(stub.user.Id) {
		return stub.user
	}
	return model2.UserDBModel{}
}

type profileUserStub struct {
	service.UserService
	current model2.UserDBModel
	saved   model2.UserDBModel
}

func (stub *profileUserStub) GetUserInfoById(string) model2.UserDBModel {
	if stub.saved.Id != 0 {
		return stub.saved
	}
	return stub.current
}

func (stub *profileUserStub) GetUserInfoByUserName(username string) model2.UserDBModel {
	if username == stub.current.Username {
		return stub.current
	}
	return model2.UserDBModel{}
}

func (stub *profileUserStub) UpdateUser(user model2.UserDBModel) {
	stub.saved = user
}

type profileRepositoryStub struct {
	service.Repository
	users service.UserService
}

func (stub profileRepositoryStub) User() service.UserService {
	return stub.users
}

func mustRefreshKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
