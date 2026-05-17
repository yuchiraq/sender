package app

import (
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionCookieName = "sender_session"

type Session struct {
	Username  string `json:"username"`
	CSRFToken string `json:"csrf_token"`
	ExpiresAt int64  `json:"expires_at"`
}

type LoginLimiter struct {
	mu        sync.Mutex
	max       int
	window    time.Duration
	block     time.Duration
	attempts  map[string][]time.Time
	blockedTo map[string]time.Time
}

func NewLoginLimiter(max int, window time.Duration, block time.Duration) *LoginLimiter {
	return &LoginLimiter{
		max:       max,
		window:    window,
		block:     block,
		attempts:  make(map[string][]time.Time),
		blockedTo: make(map[string]time.Time),
	}
}

func (l *LoginLimiter) Allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if until, exists := l.blockedTo[ip]; exists {
		if until.After(now) {
			return false, until.Sub(now)
		}
		delete(l.blockedTo, ip)
	}

	l.attempts[ip] = trimAttempts(l.attempts[ip], now, l.window)
	return true, 0
}

func (l *LoginLimiter) RegisterFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	trimmed := append(trimAttempts(l.attempts[ip], now, l.window), now)
	l.attempts[ip] = trimmed
	if len(trimmed) >= l.max {
		l.blockedTo[ip] = now.Add(l.block)
		l.attempts[ip] = nil
	}
}

func (l *LoginLimiter) Reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
	delete(l.blockedTo, ip)
}

func trimAttempts(values []time.Time, now time.Time, window time.Duration) []time.Time {
	if len(values) == 0 {
		return nil
	}

	threshold := now.Add(-window)
	filtered := values[:0]
	for _, value := range values {
		if value.After(threshold) {
			filtered = append(filtered, value)
		}
	}
	return append([]time.Time(nil), filtered...)
}

func secureCompare(left string, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func HashPassword(password string) (string, error) {
	if len(strings.TrimSpace(password)) < 8 {
		return "", errors.New("пароль должен содержать не менее 8 символов")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func IsSupportedPasswordHash(hash string) bool {
	value := strings.TrimSpace(hash)
	return strings.HasPrefix(value, "$2a$") || strings.HasPrefix(value, "$2b$") || strings.HasPrefix(value, "$2y$")
}

func verifyPassword(candidate string, plain string, hash string) bool {
	if trimmedHash := strings.TrimSpace(hash); trimmedHash != "" {
		return bcrypt.CompareHashAndPassword([]byte(trimmedHash), []byte(candidate)) == nil
	}
	return secureCompare(candidate, plain)
}

func newSessionCookie(secret string, username string, duration time.Duration) (*http.Cookie, *Session, error) {
	token, err := randomToken(24)
	if err != nil {
		return nil, nil, err
	}

	session := &Session{
		Username:  username,
		CSRFToken: token,
		ExpiresAt: time.Now().Add(duration).Unix(),
	}

	value, err := encodeSession(session, secret)
	if err != nil {
		return nil, nil, err
	}

	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(session.ExpiresAt, 0),
	}
	return cookie, session, nil
}

func expiredSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	}
}

func encodeSession(session *Session, secret string) (string, error) {
	payload, err := json.Marshal(session)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	signature := mac.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func decodeSession(value string, secret string) (*Session, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid session cookie format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := mac.Sum(nil)
	if !hmac.Equal(signature, expected) {
		return nil, errors.New("session signature mismatch")
	}

	var session Session
	if err := json.Unmarshal(payload, &session); err != nil {
		return nil, err
	}
	if time.Now().After(time.Unix(session.ExpiresAt, 0)) {
		return nil, errors.New("session expired")
	}
	return &session, nil
}

func randomToken(bytesCount int) (string, error) {
	buffer := make([]byte, bytesCount)
	if _, err := cryptorand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *App) sessionFromRequest(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, err
	}
	return decodeSession(cookie.Value, a.cfg.Auth.SessionSecret)
}

func (a *App) withAuth(next func(http.ResponseWriter, *http.Request, *Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := a.sessionFromRequest(r)
		if err != nil {
			a.clearSessionCookie(w, r)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r, session)
	}
}

func (a *App) withCSRF(next func(http.ResponseWriter, *http.Request, *Session)) http.HandlerFunc {
	return a.withAuth(func(w http.ResponseWriter, r *http.Request, session *Session) {
		if r.Method != http.MethodPost {
			http.Error(w, "метод не поддерживается", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "не удалось обработать данные формы", http.StatusBadRequest)
			return
		}
		if !sameOriginRequest(r) {
			http.Error(w, "проверка источника запроса не пройдена", http.StatusForbidden)
			return
		}
		if !secureCompare(strings.TrimSpace(r.FormValue("csrf_token")), session.CSRFToken) {
			http.Error(w, "проверка CSRF не пройдена", http.StatusForbidden)
			return
		}
		next(w, r, session)
	})
}

func (a *App) withLocalOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.Server.AllowRemote || isLoopbackClient(clientIP(r)) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "удаленный доступ отключен", http.StatusForbidden)
	})
}

func (a *App) setSessionCookie(w http.ResponseWriter, r *http.Request, cookie *http.Cookie) {
	if r.TLS != nil {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}

func (a *App) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	cookie := expiredSessionCookie()
	if r.TLS != nil {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}

func sameOriginRequest(r *http.Request) bool {
	for _, raw := range []string{r.Header.Get("Origin"), r.Header.Get("Referer")} {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		parsed, err := url.Parse(raw)
		if err != nil {
			return false
		}
		if !strings.EqualFold(parsed.Host, r.Host) {
			return false
		}
		return true
	}
	return true
}

func isLoopbackClient(value string) bool {
	if strings.EqualFold(strings.TrimSpace(value), "localhost") {
		return true
	}

	ip := net.ParseIP(strings.TrimSpace(value))
	return ip != nil && ip.IsLoopback()
}
