package apierrors

import "net/http"

type Error struct {
	Code    Code   `json:"code"`
	Status  int    `json:"status"`
	Message string `json:"message,omitempty"`
}

type Code string

var (
	CodeAuthenticationRequired Code = "AUTHENTICATION_REQUIRED"
	CodeTenantBlocked          Code = "TENANT_BLOCKED"
	CodeForbidden              Code = "FORBIDDEN"
	CodeInternalServerError    Code = "INTERNAL_SERVER_ERROR"
)

func (c Code) Status() int {
	switch c {
	case CodeAuthenticationRequired:
		return http.StatusUnauthorized
	case CodeForbidden, CodeTenantBlocked:
		return http.StatusForbidden
	case CodeInternalServerError:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

func (c Code) String() string {
	return string(c)
}

func New(code Code, message string) Error {
	return Error{
		Code:    code,
		Status:  code.Status(),
		Message: message,
	}
}
