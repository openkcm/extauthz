package session

type Session struct {
	Valid       bool
	Issuer      string
	Subject     string
	GivenName   string
	FamilyName  string
	Email       string
	Groups      []string
	AuthContext map[string]string
}
