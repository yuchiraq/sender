package app

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if _, err := a.sessionFromRequest(r); err == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		a.renderTemplate(w, "login.html", http.StatusOK, LoginPageData{
			Title:    "Вход в пульт",
			Username: strings.TrimSpace(r.URL.Query().Get("username")),
			Error:    strings.TrimSpace(r.URL.Query().Get("error")),
		})
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			a.renderTemplate(w, "login.html", http.StatusBadRequest, LoginPageData{
				Title: "Вход в пульт",
				Error: "Не удалось обработать форму входа.",
			})
			return
		}

		ip := clientIP(r)
		if allowed, retryAfter := a.limiter.Allow(ip); !allowed {
			a.renderTemplate(w, "login.html", http.StatusTooManyRequests, LoginPageData{
				Title:      "Вход в пульт",
				Username:   strings.TrimSpace(r.FormValue("username")),
				Error:      "Слишком много неудачных попыток входа.",
				RetryAfter: retryAfter.Round(time.Second).String(),
			})
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		if !secureCompare(username, a.cfg.Auth.Username) || !a.verifyAdminPassword(password) {
			a.limiter.RegisterFailure(ip)
			a.renderTemplate(w, "login.html", http.StatusUnauthorized, LoginPageData{
				Title:    "Вход в пульт",
				Username: username,
				Error:    "Неверный логин или пароль.",
			})
			return
		}

		a.limiter.Reset(ip)
		cookie, _, err := newSessionCookie(a.cfg.Auth.SessionSecret, username, time.Duration(a.cfg.Auth.SessionHours)*time.Hour)
		if err != nil {
			http.Error(w, "не удалось создать сессию", http.StatusInternalServerError)
			return
		}
		a.setSessionCookie(w, r, cookie)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "метод не поддерживается", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleDashboard(w http.ResponseWriter, r *http.Request, session *Session) {
	if r.Method != http.MethodGet {
		http.Error(w, "метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	attachments, err := a.attachmentInfos()
	if err != nil {
		attachments = nil
	}

	logs := a.store.Logs()
	if len(logs) > 12 {
		logs = logs[:12]
	}

	data := DashboardPageData{
		Title:       "Пульт рассылки",
		Username:    session.Username,
		CSRFToken:   session.CSRFToken,
		Flash:       flashFromRequest(r),
		Stats:       a.store.Stats(),
		Pending:     a.store.PendingEmails(),
		Processed:   a.store.ProcessedEmails(),
		Templates:   a.store.Templates(),
		Logs:        logs,
		Attachments: attachments,
		Runtime:     a.runtimeInfo(len(attachments)),
		Warnings:    a.warningMessages(),
	}

	if err != nil {
		data.Warnings = append(data.Warnings, fmt.Sprintf("Не удалось прочитать вложения: %v", err))
	}

	a.renderTemplate(w, "dashboard.html", http.StatusOK, data)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request, _ *Session) {
	a.clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) handleAddEmails(w http.ResponseWriter, r *http.Request, _ *Session) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		redirectWithFlash(w, r, "/", "error", "Не удалось прочитать список email-адресов.")
		return
	}

	added, skipped, err := a.store.AddPendingEmails(r.FormValue("emails"))
	if err != nil {
		redirectWithFlash(w, r, "/", "error", err.Error())
		return
	}

	message := fmt.Sprintf("В очередь добавлено адресов: %d.", added)
	if len(skipped) > 0 {
		message += " Пропущено: " + strings.Join(skipped, "; ")
	}
	redirectWithFlash(w, r, "/", "success", message)
}

func (a *App) handleRemovePendingEmail(w http.ResponseWriter, r *http.Request, _ *Session) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		redirectWithFlash(w, r, "/", "error", "Не удалось прочитать форму удаления.")
		return
	}

	if err := a.store.RemovePendingEmail(r.FormValue("address")); err != nil {
		redirectWithFlash(w, r, "/", "error", err.Error())
		return
	}

	redirectWithFlash(w, r, "/", "success", "Адрес удален из очереди.")
}

func (a *App) handleRequeueProcessedEmail(w http.ResponseWriter, r *http.Request, _ *Session) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		redirectWithFlash(w, r, "/", "error", "Не удалось прочитать форму возврата.")
		return
	}

	if err := a.store.RequeueProcessedEmail(r.FormValue("address")); err != nil {
		redirectWithFlash(w, r, "/", "error", err.Error())
		return
	}

	redirectWithFlash(w, r, "/", "success", "Адрес возвращен в очередь.")
}

func (a *App) handleAddTemplate(w http.ResponseWriter, r *http.Request, _ *Session) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		redirectWithFlash(w, r, "/", "error", "Не удалось прочитать форму шаблона.")
		return
	}

	if err := a.store.AddTemplate(r.FormValue("template_text")); err != nil {
		redirectWithFlash(w, r, "/", "error", err.Error())
		return
	}

	redirectWithFlash(w, r, "/", "success", "Новый текст добавлен в базу.")
}

func (a *App) handleRemoveTemplate(w http.ResponseWriter, r *http.Request, _ *Session) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		redirectWithFlash(w, r, "/", "error", "Не удалось прочитать форму удаления шаблона.")
		return
	}

	if err := a.store.RemoveTemplate(r.FormValue("template_id")); err != nil {
		redirectWithFlash(w, r, "/", "error", err.Error())
		return
	}

	redirectWithFlash(w, r, "/", "success", "Шаблон удален.")
}

func (a *App) handleSendNow(w http.ResponseWriter, r *http.Request, _ *Session) {
	message, err := a.processNextSend("вручную")
	if err != nil {
		redirectWithFlash(w, r, "/", "error", "Отправка не удалась: "+err.Error())
		return
	}
	if message == "" {
		redirectWithFlash(w, r, "/", "warning", "Очередь пуста, отправлять нечего.")
		return
	}
	redirectWithFlash(w, r, "/", "success", message)
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request, session *Session) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		redirectWithFlash(w, r, "/", "error", "Не удалось прочитать форму смены пароля.")
		return
	}

	if err := a.changeAdminPassword(
		r.FormValue("current_password"),
		r.FormValue("new_password"),
		r.FormValue("confirm_password"),
	); err != nil {
		redirectWithFlash(w, r, "/", "error", "Пароль не изменен: "+err.Error())
		return
	}

	_ = a.store.RecordLog("success", "", fmt.Sprintf("Пароль администратора изменен пользователем %s", session.Username))
	redirectWithFlash(w, r, "/", "success", "Пароль администратора обновлен.")
}

func flashFromRequest(r *http.Request) FlashMessage {
	return FlashMessage{
		Type:    strings.TrimSpace(r.URL.Query().Get("flash_type")),
		Message: strings.TrimSpace(r.URL.Query().Get("flash_message")),
	}
}

func redirectWithFlash(w http.ResponseWriter, r *http.Request, path string, flashType string, message string) {
	values := url.Values{}
	values.Set("flash_type", flashType)
	values.Set("flash_message", message)
	http.Redirect(w, r, path+"?"+values.Encode(), http.StatusSeeOther)
}
