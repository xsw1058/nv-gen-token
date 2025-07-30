package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// MockServer 模拟NeuVector控制器服务器
type MockServer struct {
	server *httptest.Server
}

func init() {
	log.SetFlags(23)
}

func NewMockServer() *MockServer {
	m := &MockServer{}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(RESTTokenData{
				Token: &RESTToken{Token: "test_auth_token"},
			})

		case "/v1/fed/join_token":
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if r.Header.Get("X-Auth-Token") != "test_auth_token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(RESTFedJoinToken{
				JoinToken: "test_join_token",
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return m
}

func (m *MockServer) URL() string {
	return m.server.URL
}

func (m *MockServer) Close() {
	m.server.Close()
}

func TestSendHTTPRequest(t *testing.T) {
	mock := NewMockServer()
	defer mock.Close()

	t.Run("Successful GET request", func(t *testing.T) {
		log.Println(mock.URL())
		config := RequestConfig{
			URL:           mock.URL() + "/v1/auth",
			Method:        http.MethodPost,
			Body:          RESTAuthData{Password: &RESTAuthPassword{Username: "admin", Password: "admin"}},
			ParseResponse: true,
			Insecure:      true,
		}

		var result RESTTokenData
		resp, err := SendHTTPRequest(config, &result)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		if result.Token == nil || result.Token.Token != "test_auth_token" {
			t.Errorf("Unexpected token: %v", result.Token)
		}
	})

	t.Run("Failed request", func(t *testing.T) {
		config := RequestConfig{
			URL:      "http://invalid-url",
			Method:   http.MethodGet,
			Timeout:  100 * time.Millisecond,
			Insecure: true,
		}

		_, err := SendHTTPRequest(config, nil)
		if err == nil {
			t.Error("Expected error but got none")
		}
	})
}

func TestJoinToken(t *testing.T) {
	mock := NewMockServer()
	defer mock.Close()
	j := &JoinToken{
		ServerAddress: strings.TrimPrefix(mock.URL(), ""),
		Username:      "admin",
		Password:      "admin",
	}

	t.Run("Request new token", func(t *testing.T) {
		token, err := j.requestNewToken()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if token != "test_join_token" {
			t.Errorf("Expected 'test_join_token', got '%s'", token)
		}
	})

	t.Run("Update join token", func(t *testing.T) {
		token, err := j.updateJoinToken()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if token != "test_join_token" {
			t.Errorf("Expected 'test_join_token', got '%s'", token)
		}

		if j.Token == nil || j.Token.JoinToken != "test_join_token" {
			t.Error("Token not cached correctly")
		}

		if j.Token.ExpiresAt <= time.Now().Unix() {
			t.Error("Expiration time not set correctly")
		}
	})

	t.Run("Get cached token", func(t *testing.T) {
		j.Token = &JoinTokenCache{
			JoinToken: "cached_token",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		}

		token, err := j.getJoinToken()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if token != "cached_token" {
			t.Errorf("Expected 'cached_token', got '%s'", token)
		}
	})

	t.Run("Get expired token", func(t *testing.T) {
		j.Token = &JoinTokenCache{
			JoinToken: "expired_token",
			ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
		}

		token, err := j.getJoinToken()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if token != "test_join_token" {
			t.Errorf("Expected new token, got '%s'", token)
		}
	})
}

func TestServeHTTP(t *testing.T) {
	mock := NewMockServer()
	defer mock.Close()

	j := &JoinToken{
		ServerAddress: strings.TrimPrefix(mock.URL(), ""),
		Username:      "admin",
		Password:      "admin",
	}
	j.Token = &JoinTokenCache{
		JoinToken: "initial_token",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	t.Run("Get token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/join_token", nil)
		w := httptest.NewRecorder()

		j.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var result struct {
			StatusCode int    `json:"status_code"`
			Context    string `json:"context"`
		}
		json.NewDecoder(resp.Body).Decode(&result)

		if result.Context != "initial_token" {
			t.Errorf("Expected 'initial_token', got '%s'", result.Context)
		}
	})

	t.Run("Flush token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/join_token/flush", nil)
		w := httptest.NewRecorder()

		j.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var result struct {
			StatusCode int    `json:"status_code"`
			Context    string `json:"context"`
		}
		json.NewDecoder(resp.Body).Decode(&result)

		if result.Context != "test_join_token" {
			t.Errorf("Expected new token after flush, got '%s'", result.Context)
		}
	})

	t.Run("Concurrent access", func(t *testing.T) {
		var wg sync.WaitGroup
		reqCount := 10

		wg.Add(reqCount)
		for i := 0; i < reqCount; i++ {
			go func() {
				defer wg.Done()
				req := httptest.NewRequest("GET", "/join_token", nil)
				w := httptest.NewRecorder()
				j.ServeHTTP(w, req)
			}()
		}
		wg.Wait()
	})
}

func TestSayHi(t *testing.T) {
	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	SayHi(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("Expected 'ok', got '%s'", string(body))
	}
}
