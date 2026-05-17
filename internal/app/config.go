package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const defaultFallbackPort = "127.0.0.1:60162"
const defaultAdminPassword = "change-me-now"

type Config struct {
	BaseDir   string          `json:"-"`
	Server    ServerConfig    `json:"server"`
	Auth      AuthConfig      `json:"auth"`
	SMTP      SMTPConfig      `json:"smtp"`
	Mail      MailConfig      `json:"mail"`
	Storage   StorageConfig   `json:"storage"`
	Scheduler SchedulerConfig `json:"scheduler"`
}

type ServerConfig struct {
	Address                  string `json:"address"`
	AllowRemote              bool   `json:"allow_remote"`
	ReadTimeoutSeconds       int    `json:"read_timeout_seconds"`
	ReadHeaderTimeoutSeconds int    `json:"read_header_timeout_seconds"`
	WriteTimeoutSeconds      int    `json:"write_timeout_seconds"`
	IdleTimeoutSeconds       int    `json:"idle_timeout_seconds"`
}

type AuthConfig struct {
	Username           string `json:"username"`
	Password           string `json:"password"`
	PasswordEnv        string `json:"password_env"`
	PasswordHash       string `json:"password_hash"`
	PasswordHashEnv    string `json:"password_hash_env"`
	SessionSecret      string `json:"session_secret"`
	SessionHours       int    `json:"session_hours"`
	MaxLoginAttempts   int    `json:"max_login_attempts"`
	LoginWindowMinutes int    `json:"login_window_minutes"`
	LoginBlockMinutes  int    `json:"login_block_minutes"`
}

type SMTPConfig struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	PasswordEnv        string `json:"password_env"`
	FromEmail          string `json:"from_email"`
	FromName           string `json:"from_name"`
	Security           string `json:"security"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

type MailConfig struct {
	Subject         string   `json:"subject"`
	AttachmentDir   string   `json:"attachment_dir"`
	AttachmentPaths []string `json:"attachment_paths"`
}

type StorageConfig struct {
	PendingEmailsPath   string `json:"pending_emails_path"`
	ProcessedEmailsPath string `json:"processed_emails_path"`
	TemplatesPath       string `json:"templates_path"`
	SendLogPath         string `json:"send_log_path"`
}

type SchedulerConfig struct {
	IntervalMinutes int  `json:"interval_minutes"`
	RunImmediately  bool `json:"run_immediately"`
}

func LoadConfig(path string) (Config, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("не удалось определить путь к конфигу: %w", err)
	}

	raw, err := os.ReadFile(absolutePath)
	if err != nil {
		return Config{}, fmt.Errorf("не удалось прочитать конфиг: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("не удалось разобрать конфиг: %w", err)
	}

	cfg.BaseDir = filepath.Dir(absolutePath)
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c *Config) applyDefaults() {
	if strings.TrimSpace(c.Server.Address) == "" {
		c.Server.Address = defaultFallbackPort
	}
	if c.Server.ReadTimeoutSeconds <= 0 {
		c.Server.ReadTimeoutSeconds = 10
	}
	if c.Server.ReadHeaderTimeoutSeconds <= 0 {
		c.Server.ReadHeaderTimeoutSeconds = 5
	}
	if c.Server.WriteTimeoutSeconds <= 0 {
		c.Server.WriteTimeoutSeconds = 20
	}
	if c.Server.IdleTimeoutSeconds <= 0 {
		c.Server.IdleTimeoutSeconds = 60
	}

	if strings.TrimSpace(c.Auth.Username) == "" {
		c.Auth.Username = "admin"
	}
	if c.Auth.SessionHours <= 0 {
		c.Auth.SessionHours = 12
	}
	if c.Auth.MaxLoginAttempts <= 0 {
		c.Auth.MaxLoginAttempts = 5
	}
	if c.Auth.LoginWindowMinutes <= 0 {
		c.Auth.LoginWindowMinutes = 15
	}
	if c.Auth.LoginBlockMinutes <= 0 {
		c.Auth.LoginBlockMinutes = 15
	}

	if c.SMTP.Port == 0 && strings.TrimSpace(c.SMTP.Host) != "" {
		c.SMTP.Port = 587
	}
	if strings.TrimSpace(c.SMTP.FromName) == "" {
		c.SMTP.FromName = "Почтовый сервис"
	}
	if strings.TrimSpace(c.SMTP.Security) == "" {
		c.SMTP.Security = "starttls"
	}

	if strings.TrimSpace(c.Mail.Subject) == "" {
		c.Mail.Subject = "Новый пакет материалов"
	}
	if strings.TrimSpace(c.Mail.AttachmentDir) == "" {
		c.Mail.AttachmentDir = "attachments"
	}

	if strings.TrimSpace(c.Storage.PendingEmailsPath) == "" {
		c.Storage.PendingEmailsPath = "data/pending_emails.json"
	}
	if strings.TrimSpace(c.Storage.ProcessedEmailsPath) == "" {
		c.Storage.ProcessedEmailsPath = "data/processed_emails.json"
	}
	if strings.TrimSpace(c.Storage.TemplatesPath) == "" {
		c.Storage.TemplatesPath = "data/message_templates.json"
	}
	if strings.TrimSpace(c.Storage.SendLogPath) == "" {
		c.Storage.SendLogPath = "data/send_log.json"
	}

	if c.Scheduler.IntervalMinutes <= 0 {
		c.Scheduler.IntervalMinutes = 30
	}
}

func (c Config) validate() error {
	if err := validateAddress(c.Server.Address); err != nil {
		return fmt.Errorf("некорректное значение server.address: %w", err)
	}

	if strings.TrimSpace(c.Auth.Username) == "" {
		return errors.New("поле auth.username не должно быть пустым")
	}
	if !c.HasAdminPassword() {
		return errors.New("укажите auth.password или auth.password_hash")
	}
	if hash := strings.TrimSpace(c.AdminPasswordHash()); hash != "" && !IsSupportedPasswordHash(hash) {
		return errors.New("в auth.password_hash должен быть корректный bcrypt-хэш")
	}
	if strings.TrimSpace(c.AdminPasswordHash()) == "" && len(strings.TrimSpace(c.AdminPassword())) < 8 {
		return errors.New("пароль администратора должен содержать не менее 8 символов")
	}
	if len(strings.TrimSpace(c.Auth.SessionSecret)) < 24 {
		return errors.New("поле auth.session_secret должно содержать не менее 24 символов")
	}

	if c.Scheduler.IntervalMinutes < 1 {
		return errors.New("поле scheduler.interval_minutes должно быть больше нуля")
	}

	switch strings.ToLower(strings.TrimSpace(c.SMTP.Security)) {
	case "starttls", "tls", "plain":
	default:
		return errors.New(`поле smtp.security должно быть одним из значений "starttls", "tls" или "plain"`)
	}

	if strings.TrimSpace(c.SMTP.Host) != "" {
		if c.SMTP.Port < 1 || c.SMTP.Port > 65535 {
			return errors.New("поле smtp.port должно быть в диапазоне от 1 до 65535")
		}
	}
	if c.UsesGmailSMTP() {
		if strings.EqualFold(strings.TrimSpace(c.SMTP.Security), "plain") {
			return errors.New(`для Gmail используйте smtp.security со значением "starttls" или "tls"`)
		}
		if username := strings.TrimSpace(c.SMTP.Username); username != "" {
			if _, err := mail.ParseAddress(username); err != nil {
				return errors.New("для Gmail в smtp.username нужно указать полный адрес электронной почты")
			}
		}
	}
	if strings.TrimSpace(c.SMTP.FromEmail) != "" {
		if _, err := mail.ParseAddress(c.SMTP.FromEmail); err != nil {
			return fmt.Errorf("некорректное значение smtp.from_email: %w", err)
		}
	}

	for _, path := range []string{
		c.Storage.PendingEmailsPath,
		c.Storage.ProcessedEmailsPath,
		c.Storage.TemplatesPath,
		c.Storage.SendLogPath,
	} {
		if strings.TrimSpace(path) == "" {
			return errors.New("пути в разделе storage не должны быть пустыми")
		}
	}

	return nil
}

func validateAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if strings.TrimSpace(host) == "" {
		return errors.New("адрес хоста пустой")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("порт должен быть числом: %w", err)
	}
	if portNumber < 1 || portNumber > 65535 {
		return errors.New("порт должен быть в диапазоне от 1 до 65535")
	}
	return nil
}

func (c Config) ResolvePath(path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(c.BaseDir, path))
}

func (c Config) AdminPassword() string {
	return resolveConfiguredSecret(c.Auth.Password, c.Auth.PasswordEnv)
}

func (c Config) AdminPasswordHash() string {
	return resolveConfiguredSecret(c.Auth.PasswordHash, c.Auth.PasswordHashEnv)
}

func (c Config) HasAdminPassword() bool {
	return strings.TrimSpace(c.AdminPasswordHash()) != "" || strings.TrimSpace(c.AdminPassword()) != ""
}

func (c Config) VerifyAdminPassword(candidate string) bool {
	return verifyPassword(candidate, c.AdminPassword(), c.AdminPasswordHash())
}

func (c Config) SMTPPassword() string {
	return resolveConfiguredSecret(c.SMTP.Password, c.SMTP.PasswordEnv)
}

func (c Config) UsesGmailSMTP() bool {
	return strings.EqualFold(strings.TrimSpace(c.SMTP.Host), "smtp.gmail.com")
}

func (c Config) SMTPReady() bool {
	if strings.TrimSpace(c.SMTP.Host) == "" || c.SMTP.Port <= 0 || strings.TrimSpace(c.SMTP.FromEmail) == "" {
		return false
	}

	username := strings.TrimSpace(c.SMTP.Username)
	password := strings.TrimSpace(c.SMTPPassword())

	if c.UsesGmailSMTP() {
		return username != "" && password != ""
	}

	if username == "" && password == "" {
		return true
	}

	return username != "" && password != ""
}

func (c Config) WarningMessages() []string {
	var warnings []string
	if strings.TrimSpace(c.AdminPasswordHash()) == "" {
		warnings = append(warnings, "Пароль администратора хранится в открытом виде. Для нормальной эксплуатации лучше использовать auth.password_hash или auth.password_hash_env.")
	}
	if c.VerifyAdminPassword(defaultAdminPassword) {
		warnings = append(warnings, "Установлен стандартный пароль администратора. Замените его в config.json перед публикацией сервиса наружу.")
	}
	if c.Server.AllowRemote {
		warnings = append(warnings, "Включен удаленный доступ к панели. Оставляйте этот режим только если вы понимаете сетевой контур и используете сильный пароль или bcrypt-хэш.")
	}
	if !c.SMTPReady() {
		warnings = append(warnings, "SMTP пока не настроен полностью. Веб-интерфейс будет работать, но письма не отправятся, пока вы не заполните параметры smtp.host, smtp.port и smtp.from_email.")
	}
	if c.UsesGmailSMTP() {
		warnings = append(warnings, "Для Gmail используйте пароль приложения Google, а не обычный пароль от аккаунта. Для этого в аккаунте должна быть включена двухэтапная аутентификация.")
		if strings.TrimSpace(c.SMTP.Username) == "" {
			warnings = append(warnings, "Для Gmail укажите полный адрес почты в smtp.username.")
		}
		if strings.TrimSpace(c.SMTP.FromEmail) == "" {
			warnings = append(warnings, "Для Gmail укажите адрес отправителя в smtp.from_email. Обычно это тот же адрес, что и smtp.username.")
		}
		if strings.TrimSpace(c.SMTPPassword()) == "" {
			warnings = append(warnings, "Для Gmail не задан пароль приложения. Укажите его в smtp.password или через переменную окружения из smtp.password_env.")
		}
	}
	if strings.EqualFold(strings.TrimSpace(c.SMTP.Security), "plain") {
		warnings = append(warnings, "SMTP работает в режиме plain. Для реальной эксплуатации безопаснее использовать starttls или tls.")
	}
	return warnings
}

func resolveConfiguredSecret(value string, envName string) string {
	if envName != "" {
		if envValue, ok := os.LookupEnv(envName); ok && strings.TrimSpace(envValue) != "" {
			return envValue
		}
	}
	return value
}
