package api

import (
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestBroadcasterDelivers(t *testing.T) {
	b := NewBroadcaster()
	c1, cancel1 := b.Subscribe()
	c2, cancel2 := b.Subscribe()
	defer cancel1()
	defer cancel2()
	if b.Subscribers() != 2 {
		t.Fatalf("subscribers = %d", b.Subscribers())
	}
	b.Publish(store.Event{ID: 1, Type: "asset_added"})
	for i, c := range []<-chan store.Event{c1, c2} {
		select {
		case e := <-c:
			if e.ID != 1 {
				t.Errorf("sub %d got %+v", i, e)
			}
		case <-time.After(time.Second):
			t.Errorf("sub %d timed out", i)
		}
	}
}

func TestBroadcasterSlowSubscriberDoesNotBlock(t *testing.T) {
	b := NewBroadcaster()
	_, cancelSlow := b.Subscribe() // never reads
	defer cancelSlow()
	fast, cancelFast := b.Subscribe()
	defer cancelFast()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10*subscriberBuffer; i++ {
			b.Publish(store.Event{ID: int64(i)})
			select { // keep the fast one drained
			case <-fast:
			default:
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a slow subscriber")
	}
	if b.Dropped() == 0 {
		t.Error("expected drops for the slow subscriber")
	}
}

func TestBroadcasterCancel(t *testing.T) {
	b := NewBroadcaster()
	ch, cancel := b.Subscribe()
	cancel()
	cancel() // idempotent
	if b.Subscribers() != 0 {
		t.Error("subscriber not removed")
	}
	if _, ok := <-ch; ok {
		t.Error("channel should be closed after cancel")
	}
	b.Publish(store.Event{ID: 1}) // must not panic
}

func TestBroadcasterConcurrentPublishSubscribeCancel(t *testing.T) {
	b := NewBroadcaster()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				b.Publish(store.Event{ID: int64(i)})
			}
		}
	}()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				ch, cancel := b.Subscribe()
				select {
				case <-ch:
				default:
				}
				cancel()
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
