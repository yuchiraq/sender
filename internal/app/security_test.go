package app

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHashPasswordAndVerify(t *testing.T) {
	hash, err := HashPassword("change-me-now")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	cfg := Config{
		Auth: AuthConfig{
			Username:     "admin",
			PasswordHash: hash,
		},
	}

	if !cfg.VerifyAdminPassword("change-me-now") {
		t.Fatal("expected password verification to succeed")
	}
	if cfg.VerifyAdminPassword("wrong-password") {
		t.Fatal("expected password verification to fail")
	}
}

func TestIsLoopbackClient(t *testing.T) {
	if !isLoopbackClient("127.0.0.1") {
		t.Fatal("127.0.0.1 should be loopback")
	}
	if !isLoopbackClient("::1") {
		t.Fatal("::1 should be loopback")
	}
	if !isLoopbackClient("localhost") {
		t.Fatal("localhost should be loopback")
	}
	if isLoopbackClient("192.168.1.20") {
		t.Fatal("private LAN address should not be treated as loopback")
	}
}

func TestWithCSRFAcceptsValidToken(t *testing.T) {
	app := &App{
		cfg: Config{
			Auth: AuthConfig{
				SessionSecret: "01234567890123456789012345678901",
			},
		},
	}

	cookie, session, err := newSessionCookie(app.cfg.Auth.SessionSecret, "admin", time.Hour)
	if err != nil {
		t.Fatalf("newSessionCookie returned error: %v", err)
	}

	form := url.Values{}
	form.Set("csrf_token", session.CSRFToken)

	request := httptest.NewRequest(http.MethodPost, "http://example.com/templates/remove", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://totally-different-host.example")
	request.AddCookie(cookie)

	recorder := httptest.NewRecorder()
	called := false

	handler := app.withCSRF(func(w http.ResponseWriter, r *http.Request, s *Session) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("expected handler to be called for a valid csrf token")
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, recorder.Code)
	}
}

func TestWithCSRFRejectsInvalidToken(t *testing.T) {
	app := &App{
		cfg: Config{
			Auth: AuthConfig{
				SessionSecret: "01234567890123456789012345678901",
			},
		},
	}

	cookie, _, err := newSessionCookie(app.cfg.Auth.SessionSecret, "admin", time.Hour)
	if err != nil {
		t.Fatalf("newSessionCookie returned error: %v", err)
	}

	form := url.Values{}
	form.Set("csrf_token", "wrong-token")

	request := httptest.NewRequest(http.MethodPost, "http://example.com/templates/remove", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)

	recorder := httptest.NewRecorder()
	called := false

	handler := app.withCSRF(func(w http.ResponseWriter, r *http.Request, s *Session) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("handler should not be called for an invalid csrf token")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}
