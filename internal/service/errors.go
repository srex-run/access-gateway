package service

import "errors"

var (
	ErrValidation    = errors.New("validation failed")
	ErrForbidden     = errors.New("forbidden")
	ErrStateConflict = errors.New("invalid state transition")
	ErrNotConfigured = errors.New("service not configured")
)

// RequestValidationError carries an actionable, public message. Never include
// raw database errors, credentials or asset target addresses in Message.
type RequestValidationError struct{ Message string }

func (e *RequestValidationError) Error() string { return e.Message }
func (e *RequestValidationError) Unwrap() error { return ErrValidation }

func requestValidation(message string) error { return &RequestValidationError{Message: message} }
