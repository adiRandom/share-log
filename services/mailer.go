package services

import "fmt"

type mailer struct {
}

type Mailer interface {
	EmailInviteCode(code string)
}

type MailerProvider struct {
}

func (m MailerProvider) Provide() any {
	var instance Mailer = &mailer{}
	return instance
}

func (m *mailer) EmailInviteCode(code string) {
	// TODO: Implement
	fmt.Printf("Code: %s", code)
}
