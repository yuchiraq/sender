package app

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net/mail"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxLogEntries = 250

type PendingEmail struct {
	Address string    `json:"address"`
	AddedAt time.Time `json:"added_at"`
}

type ProcessedEmail struct {
	Address     string    `json:"address"`
	AddedAt     time.Time `json:"added_at"`
	ProcessedAt time.Time `json:"processed_at"`
	Subject     string    `json:"subject"`
}

type MessageTemplate struct {
	ID      string    `json:"id"`
	Text    string    `json:"text"`
	AddedAt time.Time `json:"added_at"`
}

type SendLogEntry struct {
	At      time.Time `json:"at"`
	Email   string    `json:"email"`
	Status  string    `json:"status"`
	Details string    `json:"details"`
}

type Store struct {
	mu        sync.RWMutex
	pending   map[string]PendingEmail
	processed map[string]ProcessedEmail
	templates []MessageTemplate
	logs      []SendLogEntry
	paths     storagePaths
}

type storagePaths struct {
	pending   string
	processed string
	templates string
	logs      string
}

func NewStore(cfg Config) (*Store, error) {
	store := &Store{
		pending:   make(map[string]PendingEmail),
		processed: make(map[string]ProcessedEmail),
		paths: storagePaths{
			pending:   cfg.ResolvePath(cfg.Storage.PendingEmailsPath),
			processed: cfg.ResolvePath(cfg.Storage.ProcessedEmailsPath),
			templates: cfg.ResolvePath(cfg.Storage.TemplatesPath),
			logs:      cfg.ResolvePath(cfg.Storage.SendLogPath),
		},
	}

	if err := store.ensureFiles(); err != nil {
		return nil, err
	}
	if err := store.reload(); err != nil {
		return nil, err
	}

	return store, nil
}

func (s *Store) ensureFiles() error {
	if err := ensureJSONFile(s.paths.pending, []PendingEmail{}); err != nil {
		return fmt.Errorf("не удалось подготовить хранилище очереди: %w", err)
	}
	if err := ensureJSONFile(s.paths.processed, []ProcessedEmail{}); err != nil {
		return fmt.Errorf("не удалось подготовить хранилище архива: %w", err)
	}
	if err := ensureJSONFile(s.paths.templates, sampleTemplates()); err != nil {
		return fmt.Errorf("не удалось подготовить хранилище текстов: %w", err)
	}
	if err := ensureJSONFile(s.paths.logs, []SendLogEntry{}); err != nil {
		return fmt.Errorf("не удалось подготовить журнал событий: %w", err)
	}
	return nil
}

func (s *Store) reload() error {
	var pending []PendingEmail
	if err := readJSONFile(s.paths.pending, &pending); err != nil {
		return fmt.Errorf("не удалось загрузить очередь адресов: %w", err)
	}

	var processed []ProcessedEmail
	if err := readJSONFile(s.paths.processed, &processed); err != nil {
		return fmt.Errorf("не удалось загрузить архив адресов: %w", err)
	}

	var templates []MessageTemplate
	if err := readJSONFile(s.paths.templates, &templates); err != nil {
		return fmt.Errorf("не удалось загрузить банк текстов: %w", err)
	}

	var logs []SendLogEntry
	if err := readJSONFile(s.paths.logs, &logs); err != nil {
		return fmt.Errorf("не удалось загрузить журнал событий: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pending = make(map[string]PendingEmail, len(pending))
	for _, item := range pending {
		s.pending[item.Address] = item
	}

	s.processed = make(map[string]ProcessedEmail, len(processed))
	for _, item := range processed {
		s.processed[item.Address] = item
	}

	s.templates = templates
	s.logs = logs
	return nil
}

func (s *Store) AddPendingEmails(raw string) (int, []string, error) {
	addresses := splitEmails(raw)
	if len(addresses) == 0 {
		return 0, nil, errors.New("не найдено ни одного email-адреса")
	}

	var added int
	var skipped []string
	for _, entry := range addresses {
		if err := s.AddPendingEmail(entry); err != nil {
			skipped = append(skipped, fmt.Sprintf("%s (%v)", entry, err))
			continue
		}
		added++
	}

	if added == 0 {
		return 0, skipped, errors.New("ни один адрес не был добавлен")
	}

	return added, skipped, nil
}

func (s *Store) AddPendingEmail(raw string) error {
	address, err := normalizeEmail(raw)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.pending[address]; exists {
		return errors.New("адрес уже в очереди")
	}
	if _, exists := s.processed[address]; exists {
		return errors.New("адрес уже находится в обработанных")
	}

	s.pending[address] = PendingEmail{
		Address: address,
		AddedAt: time.Now().UTC(),
	}

	if err := s.savePendingLocked(); err != nil {
		delete(s.pending, address)
		return err
	}

	return nil
}

func (s *Store) RemovePendingEmail(raw string) error {
	address, err := normalizeEmail(raw)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.pending[address]; !exists {
		return errors.New("адрес не найден в очереди")
	}

	delete(s.pending, address)
	return s.savePendingLocked()
}

func (s *Store) RequeueProcessedEmail(raw string) error {
	address, err := normalizeEmail(raw)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.processed[address]
	if !exists {
		return errors.New("адрес не найден в обработанных")
	}

	delete(s.processed, address)
	s.pending[address] = PendingEmail{
		Address: address,
		AddedAt: time.Now().UTC(),
	}

	if err := s.savePendingLocked(); err != nil {
		delete(s.pending, address)
		s.processed[address] = entry
		return err
	}
	if err := s.saveProcessedLocked(); err != nil {
		delete(s.pending, address)
		s.processed[address] = entry
		_ = s.savePendingLocked()
		return err
	}

	return nil
}

func (s *Store) MarkProcessed(address string, subject string) error {
	normalized, err := normalizeEmail(address)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.pending[normalized]
	if !exists {
		return errors.New("адрес не найден в очереди")
	}

	delete(s.pending, normalized)
	s.processed[normalized] = ProcessedEmail{
		Address:     normalized,
		AddedAt:     entry.AddedAt,
		ProcessedAt: time.Now().UTC(),
		Subject:     subject,
	}

	if err := s.savePendingLocked(); err != nil {
		s.pending[normalized] = entry
		delete(s.processed, normalized)
		return err
	}
	if err := s.saveProcessedLocked(); err != nil {
		s.pending[normalized] = entry
		delete(s.processed, normalized)
		_ = s.savePendingLocked()
		return err
	}

	return nil
}

func (s *Store) RandomPendingEmail() (PendingEmail, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.pending) == 0 {
		return PendingEmail{}, false
	}

	items := make([]PendingEmail, 0, len(s.pending))
	for _, item := range s.pending {
		items = append(items, item)
	}

	return items[mathrand.IntN(len(items))], true
}

func (s *Store) RandomTemplate() (MessageTemplate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.templates) == 0 {
		return MessageTemplate{}, false
	}

	return s.templates[mathrand.IntN(len(s.templates))], true
}

func (s *Store) AddTemplate(text string) error {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return errors.New("текст шаблона пустой")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.templates = append(s.templates, MessageTemplate{
		ID:      newID(),
		Text:    trimmed,
		AddedAt: time.Now().UTC(),
	})

	return s.saveTemplatesLocked()
}

func (s *Store) RemoveTemplate(id string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return errors.New("не передан идентификатор шаблона")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	index := -1
	for i, item := range s.templates {
		if item.ID == trimmed {
			index = i
			break
		}
	}
	if index == -1 {
		return errors.New("шаблон не найден")
	}

	s.templates = append(s.templates[:index], s.templates[index+1:]...)
	return s.saveTemplatesLocked()
}

func (s *Store) RecordLog(status string, email string, details string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logs = append(s.logs, SendLogEntry{
		At:      time.Now().UTC(),
		Email:   strings.TrimSpace(email),
		Status:  strings.TrimSpace(status),
		Details: strings.TrimSpace(details),
	})

	if len(s.logs) > maxLogEntries {
		s.logs = s.logs[len(s.logs)-maxLogEntries:]
	}

	return s.saveLogsLocked()
}

func (s *Store) PendingEmails() []PendingEmail {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]PendingEmail, 0, len(s.pending))
	for _, item := range s.pending {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].AddedAt.After(items[j].AddedAt)
	})
	return items
}

func (s *Store) ProcessedEmails() []ProcessedEmail {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]ProcessedEmail, 0, len(s.processed))
	for _, item := range s.processed {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].ProcessedAt.After(items[j].ProcessedAt)
	})
	return items
}

func (s *Store) Templates() []MessageTemplate {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := append([]MessageTemplate(nil), s.templates...)
	sort.Slice(items, func(i, j int) bool {
		return items[i].AddedAt.After(items[j].AddedAt)
	})
	return items
}

func (s *Store) Logs() []SendLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := append([]SendLogEntry(nil), s.logs...)
	sort.Slice(items, func(i, j int) bool {
		return items[i].At.After(items[j].At)
	})
	return items
}

func (s *Store) Stats() DashboardStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return DashboardStats{
		PendingCount:   len(s.pending),
		ProcessedCount: len(s.processed),
		TemplateCount:  len(s.templates),
		LogCount:       len(s.logs),
	}
}

func (s *Store) savePendingLocked() error {
	return saveJSONAtomic(s.paths.pending, mapValuesPending(s.pending))
}

func (s *Store) saveProcessedLocked() error {
	return saveJSONAtomic(s.paths.processed, mapValuesProcessed(s.processed))
}

func (s *Store) saveTemplatesLocked() error {
	return saveJSONAtomic(s.paths.templates, s.templates)
}

func (s *Store) saveLogsLocked() error {
	return saveJSONAtomic(s.paths.logs, s.logs)
}

func mapValuesPending(values map[string]PendingEmail) []PendingEmail {
	result := make([]PendingEmail, 0, len(values))
	for _, item := range values {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].AddedAt.Before(result[j].AddedAt)
	})
	return result
}

func mapValuesProcessed(values map[string]ProcessedEmail) []ProcessedEmail {
	result := make([]ProcessedEmail, 0, len(values))
	for _, item := range values {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ProcessedAt.Before(result[j].ProcessedAt)
	})
	return result
}

func ensureJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return saveJSONAtomic(path, value)
}

func readJSONFile(path string, destination any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		raw = []byte("[]")
	}
	return json.Unmarshal(raw, destination)
}

func saveJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	tempFile, err := os.CreateTemp(filepath.Dir(path), "sender-*.tmp")
	if err != nil {
		return err
	}
	tempName := tempFile.Name()

	if _, err := tempFile.Write(payload); err != nil {
		tempFile.Close()
		_ = os.Remove(tempName)
		return err
	}
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempName)
		return err
	}

	_ = os.Remove(path)
	if err := os.Rename(tempName, path); err != nil {
		_ = os.Remove(tempName)
		return err
	}
	return nil
}

func normalizeEmail(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("email пустой")
	}

	address, err := mail.ParseAddress(trimmed)
	if err != nil {
		return "", fmt.Errorf("некорректный email: %w", err)
	}

	return strings.ToLower(address.Address), nil
}

func splitEmails(raw string) []string {
	replacer := strings.NewReplacer("\r", "\n", ",", "\n", ";", "\n", "\t", "\n", " ", "\n")
	parts := strings.Split(replacer.Replace(raw), "\n")

	seen := make(map[string]struct{})
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		candidate := strings.TrimSpace(part)
		if candidate == "" {
			continue
		}
		key := strings.ToLower(candidate)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, candidate)
	}
	return result
}

func sampleTemplates() []MessageTemplate {
	now := time.Now().UTC()
	return []MessageTemplate{
		{
			ID:      newID(),
			Text:    "Здравствуйте! Отправляем вам актуальные материалы и краткое предложение по сотрудничеству. Если удобно, ответьте на это письмо, и мы продолжим общение.",
			AddedAt: now,
		},
		{
			ID:      newID(),
			Text:    "Добрый день. Делимся свежей информацией и файлами во вложении. Если тема интересна, будем рады обсудить детали в ответном письме.",
			AddedAt: now.Add(time.Second),
		},
		{
			ID:      newID(),
			Text:    "Приветствуем! Во вложении подготовили несколько файлов для ознакомления. Напишите, если хотите получить дополнительные материалы или уточнить условия.",
			AddedAt: now.Add(2 * time.Second),
		},
	}
}

func newID() string {
	var buffer [8]byte
	if _, err := cryptorand.Read(buffer[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer[:])
}
