package keystone

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/auth"
)

var (
	// ErrInvalidCredential is returned when the auth token does not authenticate correctly.
	ErrInvalidCredential = errors.New("invalid authorization credential")

	// ErrAuthenticationFailure returned when authentication failure to be presented to agent.
	ErrAuthenticationFailure = errors.New("authentication failure")
)

type keystone struct {
	identityURL string
}

var _ auth.AccessController = &keystone{}

func (ks *keystone) Authorized(ctx context.Context, accessRecords ...auth.Access) (context.Context, error) {
	req, err := context.GetRequest(ctx)
	if err != nil {
		return nil, err
	}
	username, _, ok := req.BasicAuth()
	if !ok {
		return nil, &challenge{
			realm: ks.identityURL,
			err:   ErrInvalidCredential,
		}
	}
	return auth.WithUser(ctx, auth.UserInfo{Name: username}), nil
}

func newAccessController(options map[string]interface{}) (auth.AccessController, error) {
	identityURL, present := options["identityURL"]
	if _, ok := identityURL.(string); !present || !ok {
		return nil, fmt.Errorf(`"identityURL" must be set for keystone access controller`)
	}
	return &keystone{identityURL: identityURL.(string)}, nil
}

// challenge implements the auth.Challenge interface.
type challenge struct {
	realm string
	err   error
}

var _ auth.Challenge = challenge{}

// SetHeaders sets the basic challenge header on the response.
func (ch challenge) SetHeaders(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", ch.realm))
}

func (ch challenge) Error() string {
	return fmt.Sprintf("basic authentication challenge for realm %q: %s", ch.realm, ch.err)
}

func init() {
	auth.Register("keystone", newAccessController)
}
