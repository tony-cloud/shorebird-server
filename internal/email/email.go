package email

import (
	"fmt"
	"log"
	"net/smtp"
	"strings"
)

// Config contains SMTP settings for outbound account emails.
type Config struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

// Mailer sends account emails. When SMTP is not configured, it logs the
// message body so local self-hosted installs still expose verification links.
type Mailer struct {
	cfg Config
}

// NewMailer creates a Mailer.
func NewMailer(cfg Config) *Mailer {
	if cfg.Port == "" {
		cfg.Port = "587"
	}
	if cfg.From == "" {
		cfg.From = "shorebird@localhost"
	}
	return &Mailer{cfg: cfg}
}

// Send sends a plain-text email.
func (m *Mailer) Send(to, subject, body string) error {
	if m == nil || m.cfg.Host == "" {
		log.Printf("email disabled; would send to %s subject %q:\n%s", to, subject, body)
		return nil
	}

	msg := strings.Join([]string{
		"From: " + m.cfg.From,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	addr := fmt.Sprintf("%s:%s", m.cfg.Host, m.cfg.Port)
	var auth smtp.Auth
	if m.cfg.Username != "" {
		auth = smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	}
	return smtp.SendMail(addr, auth, m.cfg.From, []string{to}, []byte(msg))
}
