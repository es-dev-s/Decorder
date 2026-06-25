package registry

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestGraceWindowReconnect(t *testing.T) {
	var offlineCalled atomic.Bool
	var reconnectCalled atomic.Bool

	r := New(Events{
		OnClientOffline: func(string, int64) {
			offlineCalled.Store(true)
		},
		OnClientReconnected: func(string, int64) {
			reconnectCalled.Store(true)
		},
	})

	meta := ClientMeta{InfoJSON: []byte(`{"id":"abc"}`)}
	r.RegisterClient("abc", meta)
	r.UnregisterClient("abc", meta)

	if !r.InGrace("abc") {
		t.Fatal("expected client in grace after unregister")
	}

	r.RegisterClient("abc", meta)
	if r.InGrace("abc") {
		t.Fatal("grace should clear on reconnect")
	}
	if !reconnectCalled.Load() {
		t.Fatal("expected OnClientReconnected")
	}
	if offlineCalled.Load() {
		t.Fatal("offline should not fire before grace expires")
	}
}

func TestGraceExpiresOffline(t *testing.T) {
	GraceWindow = 50 * time.Millisecond
	t.Cleanup(func() { GraceWindow = 30 * time.Second })

	done := make(chan string, 1)
	r := New(Events{
		OnClientOffline: func(id string, _ int64) {
			done <- id
		},
	})

	meta := ClientMeta{InfoJSON: []byte(`{"id":"xyz"}`)}
	r.RegisterClient("xyz", meta)
	r.UnregisterClient("xyz", meta)

	select {
	case id := <-done:
		if id != "xyz" {
			t.Fatalf("offline id = %q", id)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("grace expiry did not fire client_offline")
	}
}
