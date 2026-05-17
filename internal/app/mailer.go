package app

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Mailer struct {
	cfg Config
}

func NewMailer(cfg Config) *Mailer {
	return &Mailer{cfg: cfg}
}

func (m *Mailer) Send(to string, subject string, body string, attachments []string) error {
	if !m.cfg.SMTPReady() {
		return errors.New("SMTP не настроен")
	}

	normalizedRecipient, err := normalizeEmail(to)
	if err != nil {
		return err
	}

	fromAddress := mail.Address{
		Name:    m.cfg.SMTP.FromName,
		Address: m.cfg.SMTP.FromEmail,
	}

	message, err := m.buildMessage(fromAddress, normalizedRecipient, subject, body, attachments)
	if err != nil {
		return err
	}

	return m.deliver(fromAddress.Address, normalizedRecipient, message)
}

func (m *Mailer) buildMessage(from mail.Address, to string, subject string, body string, attachments []string) ([]byte, error) {
	var buffer bytes.Buffer
	boundary := "mixed-" + newID()

	headers := textproto.MIMEHeader{}
	headers.Set("From", from.String())
	headers.Set("To", to)
	headers.Set("Subject", mime.QEncoding.Encode("utf-8", subject))
	headers.Set("Date", time.Now().Format(time.RFC1123Z))
	headers.Set("MIME-Version", "1.0")
	headers.Set("Content-Type", fmt.Sprintf(`multipart/mixed; boundary="%s"`, boundary))

	for key, values := range headers {
		for _, value := range values {
			buffer.WriteString(key)
			buffer.WriteString(": ")
			buffer.WriteString(value)
			buffer.WriteString("\r\n")
		}
	}
	buffer.WriteString("\r\n")

	buffer.WriteString("--" + boundary + "\r\n")
	buffer.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	buffer.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")

	var encodedBody bytes.Buffer
	bodyWriter := quotedprintable.NewWriter(&encodedBody)
	if _, err := bodyWriter.Write([]byte(body)); err != nil {
		return nil, err
	}
	if err := bodyWriter.Close(); err != nil {
		return nil, err
	}
	buffer.Write(encodedBody.Bytes())
	buffer.WriteString("\r\n")

	for _, path := range attachments {
		if err := appendAttachment(&buffer, boundary, path); err != nil {
			return nil, err
		}
	}

	buffer.WriteString("--" + boundary + "--\r\n")
	return buffer.Bytes(), nil
}

func appendAttachment(buffer *bytes.Buffer, boundary string, path string) error {
	payload, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("не удалось прочитать вложение %s: %w", path, err)
	}

	filename := filepath.Base(path)
	contentType := mime.TypeByExtension(strings.ToLower(filepath.Ext(filename)))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	buffer.WriteString("--" + boundary + "\r\n")
	buffer.WriteString(fmt.Sprintf("Content-Type: %s; name=%q\r\n", contentType, filename))
	buffer.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=%q\r\n", filename))
	buffer.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(payload)))
	base64.StdEncoding.Encode(encoded, payload)
	writeBase64Lines(buffer, encoded)
	buffer.WriteString("\r\n")

	return nil
}

func writeBase64Lines(buffer *bytes.Buffer, payload []byte) {
	const lineLength = 76
	for len(payload) > 0 {
		chunk := lineLength
		if len(payload) < chunk {
			chunk = len(payload)
		}
		buffer.Write(payload[:chunk])
		buffer.WriteString("\r\n")
		payload = payload[chunk:]
	}
}

func (m *Mailer) deliver(from string, to string, message []byte) error {
	address := net.JoinHostPort(m.cfg.SMTP.Host, strconv.Itoa(m.cfg.SMTP.Port))
	tlsConfig := &tls.Config{
		ServerName:         m.cfg.SMTP.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: m.cfg.SMTP.InsecureSkipVerify,
	}

	var client *smtp.Client
	var err error

	switch strings.ToLower(strings.TrimSpace(m.cfg.SMTP.Security)) {
	case "tls":
		conn, dialErr := tls.Dial("tcp", address, tlsConfig)
		if dialErr != nil {
			return dialErr
		}
		client, err = smtp.NewClient(conn, m.cfg.SMTP.Host)
	default:
		client, err = smtp.Dial(address)
		if err == nil && strings.EqualFold(strings.TrimSpace(m.cfg.SMTP.Security), "starttls") {
			err = client.StartTLS(tlsConfig)
		}
	}
	if err != nil {
		return err
	}
	defer func() {
		_ = client.Quit()
		_ = client.Close()
	}()

	if username := strings.TrimSpace(m.cfg.SMTP.Username); username != "" {
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(smtp.PlainAuth("", username, m.cfg.SMTPPassword(), m.cfg.SMTP.Host)); err != nil {
				return err
			}
		}
	}

	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}

	writer, err := client.Data()
	if err != nil {
		return err
	}

	if _, err := writer.Write(message); err != nil {
		writer.Close()
		return err
	}
	return writer.Close()
}
