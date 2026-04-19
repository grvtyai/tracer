// Package runnerclient is the Nexus-side HTTP client for the Satellite API
// defined in internal/api. It is the only place in the controller that knows
// how the wire format is serialized; the rest of the Nexus works with typed
// api.* values returned from these methods.
package runnerclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/api"
)

type Config struct {
	BaseURL   string
	AuthToken string

	// TLSFingerprint is the SHA-256 hex fingerprint of the Satellite's TLS
	// certificate (DER-encoded). When set, the client pins to this exact cert
	// and rejects any other, including valid CA-signed certs. Obtained during
	// satellite registration via TOFU.
	TLSFingerprint string

	// HTTPClient is optional. When nil, a sensible default is built (with
	// cert pinning if TLSFingerprint is set). Supply a custom client to
	// override transport behaviour entirely (e.g. during testing).
	HTTPClient *http.Client
}

type Client struct {
	baseURL   string
	authToken string
	hc        *http.Client
}

func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("runnerclient: base url required")
	}
	if cfg.AuthToken == "" {
		return nil, fmt.Errorf("runnerclient: auth token required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		if cfg.TLSFingerprint != "" {
			hc = &http.Client{
				Timeout:   30 * time.Second,
				Transport: pinnedTLSTransport(cfg.TLSFingerprint),
			}
		} else {
			hc = &http.Client{Timeout: 30 * time.Second}
		}
	}
	return &Client{
		baseURL:   strings.TrimRight(cfg.BaseURL, "/"),
		authToken: cfg.AuthToken,
		hc:        hc,
	}, nil
}

// do performs a JSON request/response round-trip. On 2xx, the body is decoded
// into out (unless out is nil). On non-2xx, an *APIError is returned.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("runnerclient: marshal body: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("runnerclient: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.authToken)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("runnerclient: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return decodeAPIError(resp)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("runnerclient: decode %s %s: %w", method, path, err)
	}
	return nil
}

// newStreamRequest issues a GET that the caller will consume as a streaming
// body (SSE). The default timeout is dropped because streams are long-lived.
func (c *Client) newStreamRequest(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("runnerclient: build stream request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.authToken)
	req.Header.Set("Accept", "text/event-stream")

	hc := c.hc
	if hc.Timeout != 0 {
		clone := *hc
		clone.Timeout = 0
		hc = &clone
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("runnerclient: stream %s: %w", path, err)
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		return nil, decodeAPIError(resp)
	}
	return resp, nil
}

// pinnedTLSTransport returns an http.Transport that accepts self-signed certs
// but rejects any cert whose SHA-256 fingerprint doesn't match want.
func pinnedTLSTransport(want string) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional: fingerprint checked below
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return fmt.Errorf("runnerclient: no peer certificate in TLS handshake")
				}
				sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
				got := hex.EncodeToString(sum[:])
				if got != want {
					return fmt.Errorf("runnerclient: TLS fingerprint mismatch (got %s)", got)
				}
				return nil
			},
		},
	}
}

func decodeAPIError(resp *http.Response) error {
	var e api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&e)
	return &APIError{
		Status:  resp.StatusCode,
		Code:    e.Code,
		Message: e.Message,
		Detail:  e.Detail,
	}
}
