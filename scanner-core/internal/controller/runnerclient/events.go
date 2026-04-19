package runnerclient

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/grvtyai/startrace/scanner-core/internal/api"
)

// Subscription is an active SSE connection to a run's event stream. Callers
// read from Events until it is closed by the client, then call Err to learn
// why the stream ended. A nil error means the server closed the stream
// normally (i.e. the run reached a terminal state).
type Subscription struct {
	// Events is closed when the stream ends for any reason.
	Events <-chan api.Event

	errCh chan error
	resp  *http.Response
}

// Err blocks until the subscription has fully terminated, then returns the
// terminal error (or nil). Must be called at most once.
func (s *Subscription) Err() error {
	return <-s.errCh
}

// Close terminates the subscription early. Safe to call concurrently with
// Events consumption.
func (s *Subscription) Close() error {
	return s.resp.Body.Close()
}

func (c *Client) SubscribeEvents(ctx context.Context, runID string) (*Subscription, error) {
	resp, err := c.newStreamRequest(ctx, "/runs/"+runID+"/events")
	if err != nil {
		return nil, err
	}
	events := make(chan api.Event, 16)
	errCh := make(chan error, 1)
	go readSSE(ctx, resp, events, errCh)
	return &Subscription{
		Events: events,
		errCh:  errCh,
		resp:   resp,
	}, nil
}

func readSSE(ctx context.Context, resp *http.Response, events chan<- api.Event, errCh chan<- error) {
	defer close(events)
	defer close(errCh)
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var dataBuf strings.Builder
	reset := func() { dataBuf.Reset() }

	dispatch := func() bool {
		defer reset()
		if dataBuf.Len() == 0 {
			return true
		}
		var ev api.Event
		if err := json.Unmarshal([]byte(dataBuf.String()), &ev); err != nil {
			errCh <- err
			return false
		}
		select {
		case events <- ev:
			return true
		case <-ctx.Done():
			errCh <- ctx.Err()
			return false
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			if !dispatch() {
				return
			}
		case strings.HasPrefix(line, ":"):
			// comment / heartbeat
		case strings.HasPrefix(line, "event:"):
			// Event type is also encoded in the JSON envelope, so we don't
			// need to track it separately — but we still accept the line to
			// stay spec-compliant.
		case strings.HasPrefix(line, "data:"):
			payload := strings.TrimPrefix(line, "data:")
			payload = strings.TrimPrefix(payload, " ")
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(payload)
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		errCh <- err
		return
	}
	errCh <- nil
}
