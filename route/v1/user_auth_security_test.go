package v1

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/authsecurity"
	passwordutil "github.com/EdmundFu-233/ReCasaOS-UserService/pkg/password"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/sqlite"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/userbootstrap"
	"github.com/EdmundFu-233/ReCasaOS-UserService/service"
	model2 "github.com/EdmundFu-233/ReCasaOS-UserService/service/model"
	"github.com/labstack/echo/v4"
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

func openSessionTestUsers(t *testing.T) *sessionTestUsers {
	t.Helper()
	db, err := sqlite.GetDb(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	users := service.NewUserService(db, userbootstrap.State{})
	if users == nil {
		t.Fatal("test user service is unavailable")
	}
	hash, err := passwordutil.Hash([]byte("session-test-password-01"))
	if err != nil {
		t.Fatal(err)
	}
	created := model2.UserDBModel{Username: "admin", Password: hash, Role: "admin"}
	if err := db.Create(&created).Error; err != nil {
		t.Fatal(err)
	}
	if created.Id < 1 {
		t.Fatal("test user has no id")
	}
	return &sessionTestUsers{UserService: users, userID: created.Id}
}

type sessionTestUsers struct {
	service.UserService
	userID int
}

func TestIssueRefreshedTokensRejectsDeletedOrRenamedUsers(t *testing.T) {
	t.Parallel()

	users := openSessionTestUsers(t)
	issued, err := users.IssueLoginSession(users.userID, time.Now())
	if err != nil {
		t.Fatalf("login issuance failed: %v", err)
	}
	privateKey, publicKey := users.GetKeyPair()
	if privateKey == nil || publicKey == nil {
		t.Fatal("test keypair is unavailable")
	}
	keyFunc := func() (*ecdsa.PublicKey, error) { return publicKey, nil }
	if _, err := authsecurity.ValidateSessionAccessToken(issued.AccessToken, keyFunc); err != nil {
		t.Fatalf("issued access token invalid: %v", err)
	}
	if _, err := authsecurity.ValidateSessionRefreshToken(issued.RefreshToken, keyFunc); err != nil {
		t.Fatalf("issued refresh token invalid: %v", err)
	}

	rotated, err := users.IssueRefreshedTokens(issued.RefreshToken, time.Now())
	if err != nil {
		t.Fatalf("valid refresh failed: %v", err)
	}
	if _, err := authsecurity.ValidateSessionRefreshToken(rotated.RefreshToken, keyFunc); err != nil {
		t.Fatalf("rotated refresh token invalid: %v", err)
	}
	// Replaying the consumed refresh token revokes the family instead of
	// minting again.
	if _, err := users.IssueRefreshedTokens(issued.RefreshToken, time.Now()); !errors.Is(err, service.ErrRefreshSessionReused) {
		t.Fatalf("replayed refresh error = %v, want ErrRefreshSessionReused", err)
	}
	// The rotated token was revoked with the family.
	if _, err := users.IssueRefreshedTokens(rotated.RefreshToken, time.Now()); !errors.Is(err, service.ErrInvalidRefreshSession) {
		t.Fatalf("post-reuse refresh error = %v, want ErrInvalidRefreshSession", err)
	}
	// An access token is never a valid refresh input.
	if _, err := users.IssueRefreshedTokens(issued.AccessToken, time.Now()); !errors.Is(err, service.ErrInvalidRefreshSession) {
		t.Fatalf("access-as-refresh error = %v, want ErrInvalidRefreshSession", err)
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

func callSessionHandler(t *testing.T, users *sessionTestUsers, handler echo.HandlerFunc, method, target, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	originalRepository := service.MyService
	service.MyService = profileRepositoryStub{users: users}
	t.Cleanup(func() { service.MyService = originalRepository })
	e := echo.New()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if token != "" {
		request.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	if err := handler(e.NewContext(request, recorder)); err != nil {
		t.Fatal(err)
	}
	return recorder
}

func loginTestTokens(t *testing.T, users *sessionTestUsers, username, password string) (int, string, string) {
	t.Helper()
	recorder := callSessionHandler(t, users,
		PostUserLogin, http.MethodPost, "/v1/users/login",
		`{"username":"`+username+`","password":"`+password+`"}`, "")
	var response struct {
		Success int `json:"success"`
		Data    struct {
			Token struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
			} `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode login response: %v: %s", err, recorder.Body.String())
	}
	return recorder.Code, response.Data.Token.AccessToken, response.Data.Token.RefreshToken
}

func TestLoginIssuesSessionAndEnforcesLockout(t *testing.T) {
	t.Parallel()

	users := openSessionTestUsers(t)
	const password = "session-test-password-01"

	code, accessToken, _ := loginTestTokens(t, users, "admin", password)
	if code != 200 || accessToken == "" {
		t.Fatalf("login status = %d, token issued = %v", code, accessToken != "")
	}

	// Unknown usernames burn the same per-key budget without distinguishing
	// the failure.
	for attempt := 1; attempt <= 4; attempt++ {
		code, _, _ := loginTestTokens(t, users, "locked-user", "wrong-password")
		if code != 400 {
			t.Fatalf("failure %d status = %d, want 400", attempt, code)
		}
	}
	recorder := callSessionHandler(t, users,
		PostUserLogin, http.MethodPost, "/v1/users/login",
		`{"username":"locked-user","password":"wrong-password"}`, "")
	if recorder.Code != 429 {
		t.Fatalf("fifth failure status = %d, want 429", recorder.Code)
	}
	if recorder.Header().Get("Retry-After") == "" {
		t.Fatal("locked login response has no Retry-After")
	}
	events := users.ListCredentialEvents(0, 100)
	var sawFailure, sawLockout, sawSuccess bool
	for _, event := range events {
		switch event.EventType {
		case model2.CredentialEventLoginFailure:
			sawFailure = true
		case model2.CredentialEventLoginLockout:
			sawLockout = true
		case model2.CredentialEventLoginSuccess:
			sawSuccess = true
		}
	}
	if !sawFailure || !sawLockout || !sawSuccess {
		t.Fatalf("audit events failure=%v lockout=%v success=%v", sawFailure, sawLockout, sawSuccess)
	}
}

func TestRefreshRotationHandlerFlow(t *testing.T) {
	t.Parallel()

	users := openSessionTestUsers(t)
	const password = "session-test-password-01"
	_, _, refresh := loginTestTokens(t, users, "admin", password)
	if refresh == "" {
		t.Fatal("login issued no refresh token")
	}
	refreshBody := func(token string) *httptest.ResponseRecorder {
		return callSessionHandler(t, users,
			PostUserRefreshToken, http.MethodPost, "/v1/users/refresh",
			`{"refresh_token":"`+token+`"}`, "")
	}

	recorder := refreshBody(refresh)
	if recorder.Code != 200 {
		t.Fatalf("refresh status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var rotated struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	// Replaying the consumed refresh token fails closed and revokes the family.
	if recorder := refreshBody(refresh); recorder.Code != 401 {
		t.Fatalf("replayed refresh status = %d, want 401", recorder.Code)
	}
	if recorder := refreshBody(rotated.Data.RefreshToken); recorder.Code != 401 {
		t.Fatalf("post-reuse refresh status = %d, want 401", recorder.Code)
	}
}

func TestLogoutRetiresOnlyThePresentingSession(t *testing.T) {
	t.Parallel()

	users := openSessionTestUsers(t)
	const password = "session-test-password-01"
	_, firstAccess, firstRefresh := loginTestTokens(t, users, "admin", password)
	_, _, secondRefresh := loginTestTokens(t, users, "admin", password)

	recorder := authenticatedSessionHandler(t, users, PostUserLogout, http.MethodPost, "/v1/users/logout", "", firstAccess)
	if recorder.Code != 200 {
		t.Fatalf("logout status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := callSessionHandler(t, users,
		PostUserRefreshToken, http.MethodPost, "/v1/users/refresh",
		`{"refresh_token":"`+firstRefresh+`"}`, ""); recorder.Code != 401 {
		t.Fatalf("logged-out refresh status = %d, want 401", recorder.Code)
	}
	recorder = callSessionHandler(t, users,
		PostUserRefreshToken, http.MethodPost, "/v1/users/refresh",
		`{"refresh_token":"`+secondRefresh+`"}`, "")
	if recorder.Code != 200 {
		t.Fatalf("sibling refresh status = %d, want 200", recorder.Code)
	}
}

func TestLogoutAllRetiresEverySession(t *testing.T) {
	t.Parallel()

	users := openSessionTestUsers(t)
	const password = "session-test-password-01"
	_, _, firstRefresh := loginTestTokens(t, users, "admin", password)
	_, secondAccess, secondRefresh := loginTestTokens(t, users, "admin", password)

	recorder := authenticatedSessionHandler(t, users, PostUserLogoutAll, http.MethodPost, "/v1/users/logout-all", "", secondAccess)
	if recorder.Code != 200 {
		t.Fatalf("logout-all status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	for name, token := range map[string]string{"first": firstRefresh, "second": secondRefresh} {
		if recorder := callSessionHandler(t, users,
			PostUserRefreshToken, http.MethodPost, "/v1/users/refresh",
			`{"refresh_token":"`+token+`"}`, ""); recorder.Code != 401 {
			t.Fatalf("%s refresh status = %d, want 401", name, recorder.Code)
		}
	}
}

func TestCredentialEventsEndpointScopesToCaller(t *testing.T) {
	t.Parallel()

	users := openSessionTestUsers(t)
	const password = "session-test-password-01"
	_, access, _ := loginTestTokens(t, users, "admin", password)

	recorder := authenticatedSessionHandler(t, users, GetCredentialEvents, http.MethodGet, "/v1/users/credential-events", "", access)
	if recorder.Code != 200 {
		t.Fatalf("events status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), model2.CredentialEventLoginSuccess) {
		t.Fatalf("events lack a login success record: %s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), password) {
		t.Fatalf("events leak the password: %s", recorder.Body.String())
	}
}

func tokenSessionID(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.JTI == "" {
		t.Fatalf("token has no jti: %v", err)
	}
	return claims.JTI
}

func authenticatedSessionHandler(t *testing.T, users *sessionTestUsers, handler echo.HandlerFunc, method, target, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	originalRepository := service.MyService
	service.MyService = profileRepositoryStub{users: users}
	t.Cleanup(func() { service.MyService = originalRepository })
	e := echo.New()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	recorder := httptest.NewRecorder()
	context := e.NewContext(request, recorder)
	if token != "" {
		context.Set(service.SessionContextKey, service.AuthenticatedSession{
			Request:  request,
			UserID:   users.userID,
			Username: "admin",
			TokenID:  tokenSessionID(t, token),
			Expires:  time.Now().Add(3 * time.Hour),
		})
	}
	if err := handler(context); err != nil {
		t.Fatal(err)
	}
	return recorder
}

func TestLoginRejectsMalformedOrOversizedBodiesWithoutReflectingSecrets(t *testing.T) {
	t.Parallel()

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
