package main

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func mockAdmin(id string) *adminConn {
	return &adminConn{
		id:       id,
		send:     make(chan wsMsg, sendQueueDepth),
		done:     make(chan struct{}),
		watching: make(map[string]struct{}),
	}
}

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

	received := 0
drain:
	for {
		select {
		case <-a.send:
			received++
		default:
			break drain
		}
	}
	if received == 0 {
		t.Fatal("expected at least one frame delivered")
	}
}

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
			h.unregisterClient(id)
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
