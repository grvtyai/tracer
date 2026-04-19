package runnerclient

import (
	"errors"
	"fmt"

	"github.com/grvtyai/startrace/scanner-core/internal/api"
)

// Sentinel errors for programmatic matching. An *APIError unwraps to one of
// these based on its Code field, so callers can use errors.Is(err, ErrNotFound)
// without caring whether the error came from the network or from the server.
var (
	ErrUnauthorized = errors.New("runnerclient: unauthorized")
	ErrNotFound     = errors.New("runnerclient: not found")
	ErrBadRequest   = errors.New("runnerclient: bad request")
	ErrConflict     = errors.New("runnerclient: conflict")
	ErrUnavailable  = errors.New("runnerclient: unavailable")
	ErrInternal     = errors.New("runnerclient: internal error")
)

// APIError is returned by every client method when the Satellite responded
// with a non-2xx status. It carries the full parsed api.ErrorResponse plus the
// HTTP status for observability.
type APIError struct {
	Status  int
	Code    string
	Message string
	Detail  string
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("runnerclient: %s (status %d, code %s): %s", e.Message, e.Status, e.Code, e.Detail)
	}
	return fmt.Sprintf("runnerclient: %s (status %d, code %s)", e.Message, e.Status, e.Code)
}

func (e *APIError) Unwrap() error {
	switch e.Code {
	case api.ErrorCodeUnauthorized, api.ErrorCodeForbidden:
		return ErrUnauthorized
	case api.ErrorCodeNotFound:
		return ErrNotFound
	case api.ErrorCodeBadRequest, api.ErrorCodeInvalidRequest, api.ErrorCodePluginMissing:
		return ErrBadRequest
	case api.ErrorCodeConflict:
		return ErrConflict
	case api.ErrorCodeUnavailable:
		return ErrUnavailable
	default:
		return ErrInternal
	}
}
