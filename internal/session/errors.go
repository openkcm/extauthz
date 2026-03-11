package session

import "errors"

var (
	ErrNotFound      = errors.New("not found")
	ErrTenantBlocked = errors.New("the tenant is blocked")
)
