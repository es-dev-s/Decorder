package main

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func mockAdmin(id string) *adminConn {
	return &adminConn{
		id:           id,
		textSend:     make(chan wsMsg, textQueueDepth),
		done:         make(chan struct{}),
		watching:     make(map[string]struct{}),
		latestFrames: make(map[string][]byte),
		framePoke:    make(chan struct{}, 1),
	}
}

// ─── Watch index ──────────────────────────────────────────────────────────────

func TestWatchIndexRouting(t *testing.T) {
	h := newHub()
	a1 := mockAdmin("admin-1")
	a2 := mockAdmin("admin-2")

	h.mu.Lock()
	h.admins[a1.id] = a1
	h.admins[a2.id] = a2
	h.mu.Unlock()

	h.addAdminWatch(a1, "client-A")
	h.addAdminWatch(a2, "client-A")
	h.addAdminWatch(a2, "client-B")

	h.mu.RLock()
	if len(h.watchIndex["client-A"]) != 2 {
		t.Fatalf("client-A watchers = %d, want 2", len(h.watchIndex["client-A"]))
	}
	if _, ok := h.watchIndex["client-A"][a1.id]; !ok {
		t.Fatal("admin-1 should watch client-A")
	}
	if _, ok := h.watchIndex["client-A"][a2.id]; !ok {
		t.Fatal("admin-2 should watch client-A")
	}
	if len(h.watchIndex["client-B"]) != 1 {
		t.Fatalf("client-B watchers = %d, want 1", len(h.watchIndex["client-B"]))
	}
	h.mu.RUnlock()
}

// ─── Frame routing ────────────────────────────────────────────────────────────

func TestRouteFrameConcurrent(t *testing.T) {
	h := newHub()
	a := mockAdmin("admin-1")
	h.mu.Lock()
	h.admins[a.id] = a
	h.mu.Unlock()
	h.addAdminWatch(a, "client-1")

	const goroutines = 50
	const framesPerG = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < framesPerG; i++ {
				data := make([]byte, 64)
				data[0] = byte(id)
				data[1] = byte(i)
				h.routeFrame("client-1", data)
			}
		}(g)
	}
	wg.Wait()

	// At least one frame should have arrived in the slot.
	a.frameMu.Lock()
	frame, ok := a.latestFrames["client-1"]
	a.frameMu.Unlock()
	if !ok || len(frame) == 0 {
		t.Fatal("expected at least one frame in latestFrames")
	}
}

// routeFrame builds one copy and shares it — no extra copies per admin.
func TestRouteFrameOneCopyShared(t *testing.T) {
	h := newHub()
	a1 := mockAdmin("admin-1")
	a2 := mockAdmin("admin-2")
	h.mu.Lock()
	h.admins[a1.id] = a1
	h.admins[a2.id] = a2
	h.mu.Unlock()
	h.addAdminWatch(a1, "client-1")
	h.addAdminWatch(a2, "client-1")

	payload := []byte("JPEG_DATA")
	h.routeFrame("client-1", payload)

	a1.frameMu.Lock()
	f1 := a1.latestFrames["client-1"]
	a1.frameMu.Unlock()
	a2.frameMu.Lock()
	f2 := a2.latestFrames["client-1"]
	a2.frameMu.Unlock()

	if f1 == nil || f2 == nil {
		t.Fatal("both admins should have the frame")
	}
	// Both admins should point to the SAME underlying array (one copy, shared).
	if &f1[0] != &f2[0] {
		t.Fatal("expected shared frame slice (one copy), got independent copies")
	}
}

// ─── Register / unregister ────────────────────────────────────────────────────

func TestConcurrentRegisterUnregister(t *testing.T) {
	h := newHub()
	const n = 100
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := "client-" + string(rune('A'+idx%26)) + string(rune('0'+idx/26))
			info := ClientInfo{ID: id, Hostname: "host", Username: "user", ConnectedAt: time.Now()}
			c := &clientConn{info: info, send: make(chan wsMsg, 4), done: make(chan struct{})}
			h.registerClient(c)
			h.routeFrame(id, []byte{1, 2, 3})
			h.unregisterClient(id, c)
		}(i)
	}
	wg.Wait()

	h.mu.RLock()
	count := len(h.clients)
	h.mu.RUnlock()
	if count != 0 {
		t.Fatalf("expected 0 clients after unregister, got %d", count)
	}
}

func TestReconnectDoesNotEvictNewConn(t *testing.T) {
	h := newHub()
	id := "client-reconnect"

	info := ClientInfo{ID: id, Hostname: "host", Username: "user", ConnectedAt: time.Now()}
	old := &clientConn{info: info, send: make(chan wsMsg, 4), done: make(chan struct{})}
	h.registerClient(old)

	newer := &clientConn{info: info, send: make(chan wsMsg, 4), done: make(chan struct{})}
	h.registerClient(newer)

	h.unregisterClient(id, old)

	h.mu.RLock()
	cur := h.clients[id]
	h.mu.RUnlock()
	if cur != newer {
		t.Fatal("unregisterClient with stale conn evicted the new connection")
	}
}

// ─── Latest-frame per-client semantics ────────────────────────────────────────

func TestLatestFrameReplacesPrevious(t *testing.T) {
	a := mockAdmin("admin-1")

	frame1 := []byte("frame-one")
	frame2 := []byte("frame-two")
	frame3 := []byte("frame-three")

	a.enqueueFrame("client-1", frame1)
	a.enqueueFrame("client-1", frame2)
	a.enqueueFrame("client-1", frame3)

	a.frameMu.Lock()
	got := a.latestFrames["client-1"]
	a.frameMu.Unlock()

	if string(got) != string(frame3) {
		t.Fatalf("expected frame3, got %s", got)
	}
}

func TestLatestFramePerClientIsolated(t *testing.T) {
	a := mockAdmin("admin-1")

	frameA := []byte("frame-A")
	frameB := []byte("frame-B")

	a.enqueueFrame("client-A", frameA)
	a.enqueueFrame("client-B", frameB)

	a.frameMu.Lock()
	gotA := a.latestFrames["client-A"]
	gotB := a.latestFrames["client-B"]
	a.frameMu.Unlock()

	if string(gotA) != string(frameA) {
		t.Fatalf("client-A: expected %s, got %s", frameA, gotA)
	}
	if string(gotB) != string(frameB) {
		t.Fatalf("client-B: expected %s, got %s", frameB, gotB)
	}
}

// ─── Cursor/stats isolation ───────────────────────────────────────────────────

func TestCursorStatsOnlyToWatchers(t *testing.T) {
	h := newHub()
	watcher := mockAdmin("watcher")
	bystander := mockAdmin("bystander")

	h.mu.Lock()
	h.admins[watcher.id] = watcher
	h.admins[bystander.id] = bystander
	h.mu.Unlock()

	h.addAdminWatch(watcher, "client-1")

	payload := []byte(`{"type":"cursor","x":100,"y":200}`)
	h.broadcastToWatchers("client-1", payload)

	select {
	case <-watcher.textSend:
	default:
		t.Fatal("watcher did not receive cursor message")
	}

	select {
	case msg := <-bystander.textSend:
		t.Fatalf("bystander received cursor message it should not: %v", msg)
	default:
	}
}

// ─── Debounce ─────────────────────────────────────────────────────────────────

func TestDebouncedBroadcast(t *testing.T) {
	h := newHub()
	info := ClientInfo{ID: "c1", ConnectedAt: time.Now()}
	c := &clientConn{info: info, send: make(chan wsMsg, 4), done: make(chan struct{})}
	h.registerClient(c)

	for i := 0; i < 50; i++ {
		h.scheduleClientListBroadcast()
	}
	time.Sleep(listDebounce + 50*time.Millisecond)

	h.listMu.Lock()
	pending := h.listTimer != nil
	h.listMu.Unlock()
	if pending {
		t.Fatal("debounce timer should have fired and cleared")
	}
}

func TestDebounceResetsOnBurst(t *testing.T) {
	h := newHub()
	a := mockAdmin("admin-1")
	h.mu.Lock()
	h.admins[a.id] = a
	h.mu.Unlock()

	for i := 0; i < 50; i++ {
		h.scheduleClientListBroadcast()
		time.Sleep(time.Millisecond)
	}
	time.Sleep(listDebounce + 60*time.Millisecond)

	received := 0
drain:
	for {
		select {
		case <-a.textSend:
			received++
		default:
			break drain
		}
	}
	if received == 0 {
		t.Fatal("expected at least one client_list broadcast")
	}
}

// ─── Concurrent client info updates ──────────────────────────────────────────

func TestUpdateClientInfoConcurrent(t *testing.T) {
	h := newHub()
	info := ClientInfo{ID: "c1", FPS: 25, Quality: 85, ConnectedAt: time.Now()}
	c := &clientConn{info: info, send: make(chan wsMsg, 4), done: make(chan struct{})}
	h.registerClient(c)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(v uint32) {
			defer wg.Done()
			h.updateClientInfo("c1", v, v, 0)
		}(uint32(i + 1))
		go func() {
			defer wg.Done()
			h.mu.RLock()
			_ = h.buildClientListJSONLocked()
			h.mu.RUnlock()
		}()
	}
	wg.Wait()
}

func TestClientListJSONValid(t *testing.T) {
	h := newHub()
	h.mu.Lock()
	h.clients["abc"] = &clientConn{
		info: ClientInfo{ID: "abc", Hostname: "h", ConnectedAt: time.Now()},
	}
	data := h.buildClientListJSONLocked()
	h.mu.Unlock()

	var msg map[string]any
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatal(err)
	}
	if msg["type"] != "client_list" {
		t.Fatalf("type = %v", msg["type"])
	}
}

// ─── Frame cleanup on disconnect ──────────────────────────────────────────────

func TestStaleFramesClearedOnClientDisconnect(t *testing.T) {
	h := newHub()
	a := mockAdmin("admin-1")
	h.mu.Lock()
	h.admins[a.id] = a
	h.mu.Unlock()

	id := "client-gone"
	info := ClientInfo{ID: id, ConnectedAt: time.Now()}
	c := &clientConn{info: info, send: make(chan wsMsg, 4), done: make(chan struct{})}
	h.registerClient(c)
	h.addAdminWatch(a, id)

	// Send a frame so the slot is populated.
	h.routeFrame(id, []byte("frame"))

	a.frameMu.Lock()
	_, had := a.latestFrames[id]
	a.frameMu.Unlock()
	if !had {
		t.Fatal("frame should be in latestFrames before disconnect")
	}

	// Client disconnects — stale frames should be purged.
	h.unregisterClient(id, c)

	a.frameMu.Lock()
	_, stillHave := a.latestFrames[id]
	a.frameMu.Unlock()
	if stillHave {
		t.Fatal("stale frame should have been removed on client disconnect")
	}
}
