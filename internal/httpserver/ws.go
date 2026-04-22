package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/augustoroman/caddylogs/internal/backend"
	"github.com/coder/websocket"
)

// hub is a trivial broadcast fan-out of backend.EventRow values to all
// currently-connected websocket clients. Slow clients are disconnected.
type hub struct {
	mu      sync.Mutex
	clients map[*client]struct{}
}

type client struct {
	send chan backend.EventRow
	done chan struct{}
}

func newHub() *hub {
	return &hub{clients: map[*client]struct{}{}}
}

func (h *hub) register() *client {
	c := &client{send: make(chan backend.EventRow, 64), done: make(chan struct{})}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	return c
}

func (h *hub) unregister(c *client) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.done)
	}
	h.mu.Unlock()
}

func (h *hub) broadcast(row backend.EventRow) {
	h.mu.Lock()
	for c := range h.clients {
		select {
		case c.send <- row:
		default:
			// Slow client: drop and let the writer goroutine notice.
		}
	}
	h.mu.Unlock()
}

func (h *hub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

func (h *hub) closeAll() {
	h.mu.Lock()
	for c := range h.clients {
		close(c.done)
	}
	h.clients = map[*client]struct{}{}
	h.mu.Unlock()
}

// handleWS upgrades an HTTP request to a websocket and starts streaming
// broadcasted events to it. The client is expected to only read; any
// messages it sends are discarded.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // same-origin by default; CORS is a bigger lift
	})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "bye")
	c := s.hub.register()
	defer s.hub.unregister(c)

	ctx := r.Context()
	// Reader goroutine: drains client messages (we don't use them) so the
	// underlying frame pipeline stays healthy.
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	// Writer loop.
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case row := <-c.send:
			wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			buf, _ := json.Marshal(map[string]any{"type": "event", "row": row})
			err := conn.Write(wctx, websocket.MessageText, buf)
			cancel()
			if err != nil {
				return
			}
		}
	}
}
