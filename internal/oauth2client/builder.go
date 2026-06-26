package oauth2client

import (
	"net/http"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/commonhttp"
)

// Builder creates an HTTP client with OAuth2 credentials for a given clientID.
type Builder func(clientID string) (*http.Client, error)

// NewBuilder returns a Builder that uses the provided OAuth2 template.
// Each invocation creates a new HTTP client with the clientID overridden.
func NewBuilder(template commoncfg.OAuth2) Builder {
	return func(clientID string) (*http.Client, error) {
		cfg := template
		cfg.Credentials.ClientID = commoncfg.SourceRef{
			Source: commoncfg.EmbeddedSourceValue,
			Value:  clientID,
		}
		return commonhttp.NewClientFromOAuth2(&cfg)
	}
}
