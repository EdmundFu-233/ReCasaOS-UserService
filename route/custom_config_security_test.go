package route

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EdmundFu-233/ReCasaOS-UserService/codegen/message_bus"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/config"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/userconfig"
	"github.com/EdmundFu-233/ReCasaOS-UserService/service"
	servicemodel "github.com/EdmundFu-233/ReCasaOS-UserService/service/model"
	commonjwt "github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"github.com/labstack/echo/v4"
)

func TestCustomConfigRouterContainsPathsAndUsesAuthenticatedIdentity(t *testing.T) {
	originalRepository := service.MyService
	originalDataPath := config.AppInfo.UserDataPath
	t.Cleanup(func() {
		service.MyService = originalRepository
		config.AppInfo.UserDataPath = originalDataPath
	})

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	users := customConfigUserStub{
		privateKey: privateKey,
		user: servicemodel.UserDBModel{
			Id:       7,
			Username: "admin",
			Role:     "admin",
		},
	}
	var publishedSystem string
	messageBusDoer := customConfigMessageBusDoer(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/zimaos:user:save_config") {
			t.Errorf("unexpected message-bus request: %s %s", request.Method, request.URL.Path)
			return customConfigMessageBusResponse(request, http.StatusBadRequest), nil
		}
		var properties map[string]string
		if err := json.NewDecoder(request.Body).Decode(&properties); err != nil {
			t.Errorf("decode message-bus body: %v", err)
			return customConfigMessageBusResponse(request, http.StatusBadRequest), nil
		}
		publishedSystem = properties["system"]
		return customConfigMessageBusResponse(request, http.StatusOK), nil
	})
	messageBusClient, err := message_bus.NewClientWithResponses(
		"http://message-bus.invalid",
		message_bus.WithHTTPClient(messageBusDoer),
	)
	if err != nil {
		t.Fatal(err)
	}
	service.MyService = customConfigRepositoryStub{users: users, messageBus: messageBusClient}

	base := t.TempDir()
	dataRoot := filepath.Join(base, "data")
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	config.AppInfo.UserDataPath = dataRoot
	sentinelPath := filepath.Join(base, "outside.json")
	sentinel := []byte(`{"outside":"sentinel"}`)
	if err := os.WriteFile(sentinelPath, sentinel, 0o600); err != nil {
		t.Fatal(err)
	}

	accessToken, err := commonjwt.GetAccessToken(users.user.Username, privateKey, users.user.Id)
	if err != nil {
		t.Fatal(err)
	}
	handler := InitRouter()
	serve := func(method, target string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, "http://device.test"+target, bytes.NewReader(body))
		request.Header.Set(echo.HeaderAuthorization, "Bearer "+accessToken)
		request.Header.Set("user_id", "999")
		if body != nil {
			request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	for _, test := range []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{name: "parent traversal get", method: http.MethodGet, path: "/v1/users/current/custom/../../outside"},
		{name: "parent traversal post", method: http.MethodPost, path: "/v1/users/current/custom/../../outside", body: []byte("changed")},
		{name: "parent traversal delete", method: http.MethodDelete, path: "/v1/users/current/custom/../../outside"},
		{name: "encoded traversal", method: http.MethodPost, path: "/v1/users/current/custom/%2e%2e%2f..%2foutside", body: []byte("changed")},
		{name: "encoded backslash", method: http.MethodPost, path: "/v1/users/current/custom/..%5coutside", body: []byte("changed")},
		{name: "absolute component", method: http.MethodPost, path: "/v1/users/current/custom//tmp/outside", body: []byte("changed")},
		{name: "nul component", method: http.MethodPost, path: "/v1/users/current/custom/system%00suffix", body: []byte("changed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := serve(test.method, test.path, test.body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("unsafe path status = %d, want 400; body=%s", response.Code, response.Body.String())
			}
			if response.Header().Get(echo.HeaderCacheControl) != "no-store" ||
				response.Header().Get(echo.HeaderXContentTypeOptions) != "nosniff" {
				t.Fatalf("missing security headers: status=%d headers=%#v", response.Code, response.Header())
			}
			if strings.Contains(response.Body.String(), "outside") {
				t.Fatalf("response reflected unsafe component: %s", response.Body.String())
			}
			got, err := os.ReadFile(sentinelPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, sentinel) {
				t.Fatalf("outside sentinel changed: %q", got)
			}
		})
	}

	payload := []byte(`{"value":"safe"}`)
	response := serve(http.MethodPost, "/v1/users/current/custom/link", payload)
	if response.Code != http.StatusOK {
		t.Fatalf("POST status = %d; body=%s", response.Code, response.Body.String())
	}
	assertCustomConfigJSONData(t, response, payload)
	filename := filepath.Join(dataRoot, "7", "link.json")
	stored, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, payload) {
		t.Fatalf("stored data = %q, want %q", stored, payload)
	}
	if _, err := os.Lstat(filepath.Join(dataRoot, "999")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("forged header selected a storage directory: %v", err)
	}

	response = serve(http.MethodGet, "/v1/users/current/custom/link", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("GET status/body = %d %s", response.Code, response.Body.String())
	}
	assertCustomConfigJSONData(t, response, payload)
	for _, document := range []struct {
		key  string
		data json.RawMessage
	}{
		{key: "tips_state", data: json.RawMessage(`true`)},
		{key: "app_order", data: json.RawMessage(`["terminal","files"]`)},
		{key: "widgets_config", data: json.RawMessage(`{"weather":{"enabled":true}}`)},
	} {
		response = serve(http.MethodPost, "/v1/users/current/custom/"+document.key, document.data)
		if response.Code != http.StatusOK {
			t.Fatalf("POST %s status = %d; body=%s", document.key, response.Code, response.Body.String())
		}
		assertCustomConfigJSONData(t, response, document.data)
		response = serve(http.MethodGet, "/v1/users/current/custom/"+document.key, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d; body=%s", document.key, response.Code, response.Body.String())
		}
		assertCustomConfigJSONData(t, response, document.data)
	}
	systemDocument := json.RawMessage(`{"language":"en_us"}`)
	response = serve(http.MethodPost, "/v1/users/current/custom/system", systemDocument)
	if response.Code != http.StatusOK {
		t.Fatalf("POST system status = %d; body=%s", response.Code, response.Body.String())
	}
	assertCustomConfigJSONData(t, response, systemDocument)
	if publishedSystem != string(systemDocument) {
		t.Fatalf("published system data = %q, want %q", publishedSystem, systemDocument)
	}

	response = serve(http.MethodPost, "/v1/users/current/custom/link", bytes.Repeat([]byte{'x'}, userconfig.MaxConfigBytes+1))
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized POST status = %d; body=%s", response.Code, response.Body.String())
	}
	stored, err = os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, payload) {
		t.Fatal("oversized POST changed the existing configuration")
	}

	response = serve(http.MethodDelete, "/v1/users/current/custom/link", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d; body=%s", response.Code, response.Body.String())
	}
	if _, err := os.Lstat(filename); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("configuration still exists after DELETE: %v", err)
	}
	response = serve(http.MethodGet, "/v1/users/current/custom/link", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("missing GET status = %d; body=%s", response.Code, response.Body.String())
	}
	var missingEnvelope struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &missingEnvelope); err != nil {
		t.Fatal(err)
	}
	if missingEnvelope.Data != "" {
		t.Fatalf("missing GET data = %q, want empty string", missingEnvelope.Data)
	}
}

type customConfigUserStub struct {
	service.UserService
	privateKey *ecdsa.PrivateKey
	user       servicemodel.UserDBModel
}

func (stub customConfigUserStub) GetKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	return stub.privateKey, &stub.privateKey.PublicKey
}

func (stub customConfigUserStub) GetUserInfoById(id string) servicemodel.UserDBModel {
	if id == "7" {
		return stub.user
	}
	return servicemodel.UserDBModel{}
}

type customConfigRepositoryStub struct {
	service.Repository
	users      service.UserService
	messageBus *message_bus.ClientWithResponses
}

func (stub customConfigRepositoryStub) User() service.UserService {
	return stub.users
}

func (stub customConfigRepositoryStub) MessageBus() *message_bus.ClientWithResponses {
	return stub.messageBus
}

func assertCustomConfigJSONData(t *testing.T, response *httptest.ResponseRecorder, want json.RawMessage) {
	t.Helper()
	if response.Header().Get(echo.HeaderCacheControl) != "no-store" ||
		response.Header().Get(echo.HeaderXContentTypeOptions) != "nosniff" {
		t.Fatalf("missing custom-config security headers: %#v", response.Header())
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(envelope.Data, want) {
		t.Fatalf("response data = %s, want %s", envelope.Data, want)
	}
}

type customConfigMessageBusDoer func(*http.Request) (*http.Response, error)

func (doer customConfigMessageBusDoer) Do(request *http.Request) (*http.Response, error) {
	return doer(request)
}

func customConfigMessageBusResponse(request *http.Request, status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    request,
	}
}
