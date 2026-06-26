package session

import "github.com/openkcm/extauthz/internal/oauth2client"

type ManagerOption func(*Manager)

func WithOAuth2ClientBuilder(b oauth2client.Builder) ManagerOption {
	return func(m *Manager) {
		m.newCreds = b
	}
}
