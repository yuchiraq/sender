package app

import (
	"path/filepath"
	"testing"
)

func TestChangeAdminPasswordPersistsHashToConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	initialHash, err := HashPassword("старый-пароль")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	cfg := Config{
		BaseDir: tempDir,
		Server: ServerConfig{
			Address: "127.0.0.1:60162",
		},
		Auth: AuthConfig{
			Username:      "admin",
			PasswordHash:  initialHash,
			SessionSecret: "01234567890123456789012345678901",
		},
		Storage: StorageConfig{
			PendingEmailsPath:   "data/pending.json",
			ProcessedEmailsPath: "data/processed.json",
			TemplatesPath:       "data/templates.json",
			SendLogPath:         "data/logs.json",
		},
		Scheduler: SchedulerConfig{
			IntervalMinutes: 30,
		},
	}

	if err := SaveConfig(configPath, cfg); err != nil {
		t.Fatalf("SaveConfig returned error: %v", err)
	}

	app := &App{
		cfg:        cfg,
		configPath: configPath,
	}

	if err := app.changeAdminPassword("старый-пароль", "новый-пароль-123", "новый-пароль-123"); err != nil {
		t.Fatalf("changeAdminPassword returned error: %v", err)
	}

	updated, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if !updated.VerifyAdminPassword("новый-пароль-123") {
		t.Fatal("expected new password to be persisted")
	}
	if updated.VerifyAdminPassword("старый-пароль") {
		t.Fatal("expected old password to stop working")
	}
	if updated.Auth.Password != "" {
		t.Fatal("expected plain password to be cleared from config")
	}
}
