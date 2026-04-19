package api

// Well-known error codes. The Nexus matches on Code for programmatic handling
// (e.g. prompt the operator to re-auth on ErrorCodeUnauthorized) and falls back
// to displaying Message for anything unrecognized.
const (
	ErrorCodeBadRequest     = "bad_request"
	ErrorCodeUnauthorized   = "unauthorized"
	ErrorCodeForbidden      = "forbidden"
	ErrorCodeNotFound       = "not_found"
	ErrorCodeConflict       = "conflict"
	ErrorCodeUnavailable    = "unavailable"
	ErrorCodeInternal       = "internal"
	ErrorCodePluginMissing  = "plugin_missing"
	ErrorCodeInvalidRequest = "invalid_request"
)

// ErrorResponse is the body returned with any non-2xx HTTP status.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}
