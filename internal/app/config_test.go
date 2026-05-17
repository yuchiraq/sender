package app

import (
	"strings"
	"testing"
)

func TestSMTPReadyForGmailRequiresCredentials(t *testing.T) {
	cfg := Config{
		SMTP: SMTPConfig{
			Host:      "smtp.gmail.com",
			Port:      587,
			Username:  "user@gmail.com",
			FromEmail: "user@gmail.com",
			Security:  "starttls",
		},
	}

	if cfg.SMTPReady() {
		t.Fatal("gmail should not be ready without an app password")
	}

	cfg.SMTP.Password = "app-password"
	if !cfg.SMTPReady() {
		t.Fatal("gmail should be ready when username, from_email and password are present")
	}
}

func TestWarningMessagesForGmailIncludeAppPasswordHint(t *testing.T) {
	cfg := Config{
		Auth: AuthConfig{
			Username:      "admin",
			PasswordHash:  "$2a$10$752KesCo.TmOLZWapEXUSOG6addXivwgVRss6rWrHG6tYK3nNPJHO",
			SessionSecret: "01234567890123456789012345678901",
		},
		SMTP: SMTPConfig{
			Host:      "smtp.gmail.com",
			Port:      587,
			Username:  "",
			FromEmail: "",
			Security:  "starttls",
		},
	}

	warnings := cfg.WarningMessages()
	joined := strings.Join(warnings, "\n")

	if joined == "" {
		t.Fatal("expected warnings for incomplete Gmail configuration")
	}
	if !strings.Contains(joined, "пароль приложения") {
		t.Fatal("expected Gmail app password warning")
	}
}
