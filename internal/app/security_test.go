package app

import (
	"net/http/httptest"
	"testing"
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

func TestSameOriginRequest(t *testing.T) {
	request := httptest.NewRequest("POST", "http://127.0.0.1:60162/send-now", nil)
	request.Host = "127.0.0.1:60162"
	request.Header.Set("Origin", "http://127.0.0.1:60162")
	if !sameOriginRequest(request) {
		t.Fatal("same origin request should pass")
	}

	request.Header.Set("Origin", "http://evil.example")
	if sameOriginRequest(request) {
		t.Fatal("foreign origin request should fail")
	}
}

func TestSameOriginRequestBehindReverseProxy(t *testing.T) {
	request := httptest.NewRequest("POST", "http://127.0.0.1:60162/templates/remove", nil)
	request.Host = "127.0.0.1:60162"
	request.Header.Set("Origin", "https://mail.example.com")
	request.Header.Set("X-Forwarded-Host", "mail.example.com")
	request.Header.Set("X-Forwarded-Proto", "https")

	if !sameOriginRequest(request) {
		t.Fatal("request forwarded by a reverse proxy should pass same-origin validation")
	}
}

func TestSameOriginRequestDefaultHttpsPort(t *testing.T) {
	request := httptest.NewRequest("POST", "http://127.0.0.1:60162/templates/remove", nil)
	request.Host = "127.0.0.1:60162"
	request.Header.Set("Referer", "https://mail.example.com/dashboard")
	request.Header.Set("X-Forwarded-Host", "mail.example.com:443")
	request.Header.Set("X-Forwarded-Proto", "https")

	if !sameOriginRequest(request) {
		t.Fatal("https referer without explicit port should match forwarded host with 443")
	}
}
