package cmd

// Many thanks to the original authors of this code
// https://github.com/go-acme/lego/blob/83c626d9a1889fa499bc9c97bc2fdea965307002/cmd/account.go#L10

import (
	"crypto"

	"github.com/go-acme/lego/v4/registration"
)

// Account represents a users local saved credentials.
type Account struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	Key          crypto.PrivateKey      `json:"-"`
}

/** Implementation of the registration.User interface **/

// GetEmail returns the email address for the account.
func (a *Account) GetEmail() string {
	return a.Email
}

// GetPrivateKey returns the private RSA account key.
func (a *Account) GetPrivateKey() crypto.PrivateKey {
	return a.Key
}

// GetRegistration returns the server registration.
func (a *Account) GetRegistration() *registration.Resource {
	return a.Registration
}

/** End **/
