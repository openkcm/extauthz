package oidc

import "errors"

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrNoProvider   = errors.New("no provider")
)
