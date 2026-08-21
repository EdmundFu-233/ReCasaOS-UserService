package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/userbootstrap"
	"github.com/labstack/echo/v4"
)

func TestNetworkRegistrationIsPermanentlyGoneAndDoesNotReflectSecrets(t *testing.T) {
	e := echo.New()
	request := httptest.NewRequest(http.MethodPost, "/v1/users/register", strings.NewReader(`{"username":"admin","password":"do-not-reflect","key":"do-not-reflect-key"}`))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	recorder := httptest.NewRecorder()
	ctx := e.NewContext(request, recorder)

	if err := PostUserRegister(ctx); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", recorder.Code)
	}
	assertNoStore(t, recorder)
	body := recorder.Body.String()
	for _, forbidden := range []string{"do-not-reflect", "do-not-reflect-key", `"key"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response disclosed forbidden value %q: %s", forbidden, body)
		}
	}
}

func TestStatusReturnsOnlyInitializedBoolean(t *testing.T) {
	for _, initialized := range []bool{false, true} {
		t.Run(map[bool]string{false: "pristine", true: "initialized"}[initialized], func(t *testing.T) {
			status := userbootstrap.StatusPristine
			if initialized {
				status = userbootstrap.StatusInitialized
			}
			e := echo.New()
			request := httptest.NewRequest(http.MethodGet, "/v1/users/status", nil)
			recorder := httptest.NewRecorder()
			ctx := e.NewContext(request, recorder)
			if err := getUserStatus(ctx, stubInitializationStateReader{state: userbootstrap.State{Status: status}}); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d", recorder.Code)
			}
			assertNoStore(t, recorder)
			var response struct {
				Data map[string]any `json:"data"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if len(response.Data) != 1 || response.Data["initialized"] != initialized {
				t.Fatalf("status data = %#v", response.Data)
			}
			for _, forbidden := range []string{"key", "gpus", "setup_required", "installation_id"} {
				if _, exists := response.Data[forbidden]; exists {
					t.Fatalf("status response contains %q: %#v", forbidden, response.Data)
				}
			}
		})
	}
}

func TestRecoveryStatusFailsClosedWithoutErrorDetails(t *testing.T) {
	e := echo.New()
	request := httptest.NewRequest(http.MethodGet, "/v1/users/status", nil)
	recorder := httptest.NewRecorder()
	ctx := e.NewContext(request, recorder)
	wantErr := errors.New("sensitive database path /secret/user.db")
	if err := getUserStatus(ctx, stubInitializationStateReader{err: wantErr}); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
	assertNoStore(t, recorder)
	if strings.Contains(recorder.Body.String(), wantErr.Error()) || strings.Contains(recorder.Body.String(), "/secret") {
		t.Fatalf("error response disclosed details: %s", recorder.Body.String())
	}
}

type stubInitializationStateReader struct {
	state userbootstrap.State
	err   error
}

func (reader stubInitializationStateReader) GetInitializationState(context.Context) (userbootstrap.State, error) {
	return reader.state, reader.err
}

func assertNoStore(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if recorder.Header().Get(echo.HeaderCacheControl) != "no-store" || recorder.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("cache headers = %q / %q", recorder.Header().Get(echo.HeaderCacheControl), recorder.Header().Get("Pragma"))
	}
}
