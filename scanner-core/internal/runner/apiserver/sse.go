package apiserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/api"
)

// streamSSE writes events from ch to w as Server-Sent Events until either ch
// closes or the request context is cancelled. A heartbeat comment is sent
// periodically so proxies and clients don't treat the stream as stalled.
func streamSSE(w http.ResponseWriter, r *http.Request, ch <-chan api.Event) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, api.ErrorCodeInternal, "streaming not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
