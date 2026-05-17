package app

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed assets/templates/*.html assets/static/*.css
var embeddedAssets embed.FS

type App struct {
	cfg        Config
	configPath string
	store      *Store
	mailer     *Mailer
	logger     *log.Logger
	templates  map[string]*template.Template
	static     http.Handler
	limiter    *LoginLimiter
	sendMu     sync.Mutex
	authMu     sync.RWMutex
}

type DashboardStats struct {
	PendingCount   int
	ProcessedCount int
	TemplateCount  int
	LogCount       int
}

type FlashMessage struct {
	Type    string
	Message string
}

type AttachmentInfo struct {
	Name string
	Path string
	Size string
}

type RuntimeInfo struct {
	ListenAddress string
	IntervalLabel string
	SMTPMode      string
	SMTPReady     bool
	AttachmentSet string
	AccessMode    string
	PasswordMode  string
}

type LoginPageData struct {
	Title      string
	Username   string
	Error      string
	RetryAfter string
}

type DashboardPageData struct {
	Title       string
	Username    string
	CSRFToken   string
	Flash       FlashMessage
	Stats       DashboardStats
	Pending     []PendingEmail
	Processed   []ProcessedEmail
	Templates   []MessageTemplate
	Logs        []SendLogEntry
	Attachments []AttachmentInfo
	Runtime     RuntimeInfo
	Warnings    []string
}

func New(configPath string) (*App, error) {
	resolvedConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("не удалось определить путь к конфигу: %w", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}

	store, err := NewStore(cfg)
	if err != nil {
		return nil, err
	}

	templates, err := loadTemplates()
	if err != nil {
		return nil, err
	}

	staticRoot, err := fs.Sub(embeddedAssets, "assets/static")
	if err != nil {
		return nil, fmt.Errorf("не удалось подготовить статические файлы: %w", err)
	}

	logger := log.New(os.Stdout, "sender: ", log.LstdFlags)
	for _, warning := range cfg.WarningMessages() {
		logger.Printf("предупреждение: %s", warning)
	}

	return &App{
		cfg:        cfg,
		configPath: resolvedConfigPath,
		store:      store,
		mailer:     NewMailer(cfg),
		logger:     logger,
		templates:  templates,
		static:     http.StripPrefix("/static/", http.FileServer(http.FS(staticRoot))),
		limiter: NewLoginLimiter(
			cfg.Auth.MaxLoginAttempts,
			time.Duration(cfg.Auth.LoginWindowMinutes)*time.Minute,
			time.Duration(cfg.Auth.LoginBlockMinutes)*time.Minute,
		),
	}, nil
}

func loadTemplates() (map[string]*template.Template, error) {
	funcMap := template.FuncMap{
		"formatTime": func(value time.Time) string {
			if value.IsZero() {
				return "-"
			}
			return value.Local().Format("02.01.2006 15:04:05")
		},
		"statusClass": func(status string) string {
			switch strings.ToLower(strings.TrimSpace(status)) {
			case "success":
				return "status-success"
			case "error":
				return "status-error"
			case "warning":
				return "status-warning"
			default:
				return "status-muted"
			}
		},
		"truncate": func(value string, limit int) string {
			if len(value) <= limit {
				return value
			}
			return strings.TrimSpace(value[:limit]) + "..."
		},
	}

	files := []string{"login.html", "dashboard.html"}
	result := make(map[string]*template.Template, len(files))
	for _, file := range files {
		tmpl, err := template.New(file).Funcs(funcMap).ParseFS(embeddedAssets, "assets/templates/"+file)
		if err != nil {
			return nil, fmt.Errorf("не удалось разобрать шаблон %s: %w", file, err)
		}
		result[file] = tmpl
	}
	return result, nil
}

func (a *App) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a.startScheduler(ctx)

	server := &http.Server{
		Addr:              a.cfg.Server.Address,
		Handler:           a.routes(),
		ReadTimeout:       time.Duration(a.cfg.Server.ReadTimeoutSeconds) * time.Second,
		ReadHeaderTimeout: time.Duration(a.cfg.Server.ReadHeaderTimeoutSeconds) * time.Second,
		WriteTimeout:      time.Duration(a.cfg.Server.WriteTimeoutSeconds) * time.Second,
		IdleTimeout:       time.Duration(a.cfg.Server.IdleTimeoutSeconds) * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	a.logger.Printf("сервис запущен на http://%s", a.cfg.Server.Address)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (a *App) startScheduler(ctx context.Context) {
	interval := time.Duration(a.cfg.Scheduler.IntervalMinutes) * time.Minute
	ticker := time.NewTicker(interval)

	a.logger.Printf("интервал планировщика: %s", interval)

	go func() {
		defer ticker.Stop()

		if a.cfg.Scheduler.RunImmediately {
			if message, err := a.processNextSend("при запуске"); err != nil {
				a.logger.Printf("ошибка отправки при запуске: %v", err)
			} else if message != "" {
				a.logger.Print(message)
			}
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if message, err := a.processNextSend("по расписанию"); err != nil {
					a.logger.Printf("ошибка отправки по расписанию: %v", err)
				} else if message != "" {
					a.logger.Print(message)
				}
			}
		}
	}()
}

func (a *App) processNextSend(trigger string) (string, error) {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()

	if !a.cfg.SMTPReady() {
		return "", fmt.Errorf("SMTP настроен не полностью")
	}

	pending, ok := a.store.RandomPendingEmail()
	if !ok {
		return "", nil
	}

	templateItem, ok := a.store.RandomTemplate()
	if !ok {
		return "", fmt.Errorf("в базе нет текстов для отправки")
	}

	attachments, err := a.resolvedAttachmentPaths()
	if err != nil {
		return "", err
	}

	if err := a.mailer.Send(pending.Address, a.cfg.Mail.Subject, templateItem.Text, attachments); err != nil {
		_ = a.store.RecordLog("error", pending.Address, fmt.Sprintf("%s: %v", trigger, err))
		return "", err
	}

	if err := a.store.MarkProcessed(pending.Address, a.cfg.Mail.Subject); err != nil {
		_ = a.store.RecordLog("error", pending.Address, fmt.Sprintf("%s: письмо отправлено, но очередь не обновилась: %v", trigger, err))
		return "", err
	}

	message := fmt.Sprintf("Письмо отправлено на %s", pending.Address)
	_ = a.store.RecordLog("success", pending.Address, fmt.Sprintf("%s: шаблон %s, вложений %d", trigger, templateItem.ID, len(attachments)))
	return message, nil
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/static/", a.static)
	mux.HandleFunc("/healthz", a.handleHealth)
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/", a.withAuth(a.handleDashboard))
	mux.HandleFunc("/logout", a.withCSRF(a.handleLogout))
	mux.HandleFunc("/emails", a.withCSRF(a.handleAddEmails))
	mux.HandleFunc("/emails/remove", a.withCSRF(a.handleRemovePendingEmail))
	mux.HandleFunc("/processed/requeue", a.withCSRF(a.handleRequeueProcessedEmail))
	mux.HandleFunc("/templates", a.withCSRF(a.handleAddTemplate))
	mux.HandleFunc("/templates/remove", a.withCSRF(a.handleRemoveTemplate))
	mux.HandleFunc("/send-now", a.withCSRF(a.handleSendNow))
	mux.HandleFunc("/settings/password", a.withCSRF(a.handleChangePassword))

	return a.withSecureHeaders(a.withLocalOnly(mux))
}

func (a *App) withSecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'self'; frame-ancestors 'none'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) renderTemplate(w http.ResponseWriter, name string, status int, data any) {
	tmpl, exists := a.templates[name]
	if !exists {
		http.Error(w, "шаблон не найден", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "не удалось отрисовать шаблон", http.StatusInternalServerError)
	}
}

func (a *App) resolvedAttachmentPaths() ([]string, error) {
	if len(a.cfg.Mail.AttachmentPaths) > 0 {
		paths := make([]string, 0, len(a.cfg.Mail.AttachmentPaths))
		for _, item := range a.cfg.Mail.AttachmentPaths {
			resolved := a.cfg.ResolvePath(item)
			info, err := os.Stat(resolved)
			if err != nil {
				return nil, fmt.Errorf("не удалось открыть вложение %s: %w", resolved, err)
			}
			if info.IsDir() {
				return nil, fmt.Errorf("путь к вложению %s указывает на папку, а не на файл", resolved)
			}
			paths = append(paths, resolved)
		}
		sort.Strings(paths)
		return paths, nil
	}

	root := a.cfg.ResolvePath(a.cfg.Mail.AttachmentDir)
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать папку вложений: %w", err)
	}

	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		paths = append(paths, filepath.Join(root, entry.Name()))
	}
	sort.Strings(paths)
	return paths, nil
}

func (a *App) attachmentInfos() ([]AttachmentInfo, error) {
	paths, err := a.resolvedAttachmentPaths()
	if err != nil {
		return nil, err
	}

	items := make([]AttachmentInfo, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		items = append(items, AttachmentInfo{
			Name: filepath.Base(path),
			Path: path,
			Size: humanSize(info.Size()),
		})
	}
	return items, nil
}

func (a *App) runtimeInfo(attachmentCount int) RuntimeInfo {
	attachmentMode := fmt.Sprintf("%d файлов", attachmentCount)
	if len(a.cfg.Mail.AttachmentPaths) > 0 {
		attachmentMode = fmt.Sprintf("фиксированный список, %d файлов", attachmentCount)
	} else {
		attachmentMode = fmt.Sprintf("все файлы из папки, %d файлов", attachmentCount)
	}

	return RuntimeInfo{
		ListenAddress: a.cfg.Server.Address,
		IntervalLabel: fmt.Sprintf("%d мин.", a.cfg.Scheduler.IntervalMinutes),
		SMTPMode:      a.smtpModeLabel(),
		SMTPReady:     a.cfg.SMTPReady(),
		AttachmentSet: attachmentMode,
		AccessMode:    map[bool]string{true: "удаленный доступ открыт", false: "только локально"}[a.cfg.Server.AllowRemote],
		PasswordMode:  a.passwordModeLabel(),
	}
}

func (a *App) smtpModeLabel() string {
	mode := strings.ToUpper(strings.TrimSpace(a.cfg.SMTP.Security))
	if a.cfg.UsesGmailSMTP() {
		if mode == "" {
			return "Gmail"
		}
		return "Gmail через " + mode
	}
	if mode == "" {
		return "не задан"
	}
	return mode
}

func (a *App) verifyAdminPassword(candidate string) bool {
	a.authMu.RLock()
	defer a.authMu.RUnlock()
	return a.cfg.VerifyAdminPassword(candidate)
}

func (a *App) warningMessages() []string {
	a.authMu.RLock()
	defer a.authMu.RUnlock()
	return a.cfg.WarningMessages()
}

func (a *App) passwordModeLabel() string {
	a.authMu.RLock()
	defer a.authMu.RUnlock()

	if strings.TrimSpace(a.cfg.AdminPasswordHash()) != "" {
		return "bcrypt-хэш"
	}
	return "обычный пароль"
}

func (a *App) changeAdminPassword(currentPassword string, newPassword string, confirmPassword string) error {
	currentPassword = strings.TrimSpace(currentPassword)
	newPassword = strings.TrimSpace(newPassword)
	confirmPassword = strings.TrimSpace(confirmPassword)

	if currentPassword == "" {
		return fmt.Errorf("введите текущий пароль")
	}
	if newPassword == "" {
		return fmt.Errorf("введите новый пароль")
	}
	if newPassword != confirmPassword {
		return fmt.Errorf("новый пароль и подтверждение не совпадают")
	}
	if !a.verifyAdminPassword(currentPassword) {
		return fmt.Errorf("текущий пароль указан неверно")
	}

	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	a.authMu.RLock()
	updatedConfig := a.cfg
	a.authMu.RUnlock()

	updatedConfig.Auth.Password = ""
	updatedConfig.Auth.PasswordEnv = ""
	updatedConfig.Auth.PasswordHash = hash
	updatedConfig.Auth.PasswordHashEnv = ""

	if err := SaveConfig(a.configPath, updatedConfig); err != nil {
		return err
	}

	a.authMu.Lock()
	a.cfg.Auth = updatedConfig.Auth
	a.authMu.Unlock()

	return nil
}

func humanSize(size int64) string {
	const unit = 1024
	if size < unit {
		return strconv.FormatInt(size, 10) + " B"
	}

	div, exp := int64(unit), 0
	for value := size / unit; value >= unit; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}
