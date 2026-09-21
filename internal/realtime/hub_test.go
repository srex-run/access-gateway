package realtime

import "testing"

func TestHubRecipientIsolationAndDisconnect(t *testing.T) {
	hub := NewHub()
	one, cancelOne, _ := hub.Subscribe("one")
	two, cancelTwo, _ := hub.Subscribe("two")
	defer cancelOne()
	defer cancelTwo()
	hub.Publish(Change{Topic: "notifications", UserID: "one"})
	if event := <-one; event.Topic != "notifications" || event.UserID != "one" {
		t.Fatalf("wrong event: %+v", event)
	}
	select {
	case event := <-two:
		t.Fatalf("another user's event leaked: %+v", event)
	default:
	}
	hub.Publish(Change{Topic: "catalog"})
	<-one
	<-two
	cancelOne()
	cancelOne()
	if _, open := <-one; open {
		t.Fatal("unsubscribe did not close the stream")
	}
	hub.setAvailable(false)
	if _, open := <-two; open {
		t.Fatal("database outage did not disconnect clients")
	}
	if _, cancel, available := hub.Subscribe("three"); available {
		cancel()
		t.Fatal("accepted subscriber while database listener was down")
	}
	hub.setAvailable(true)
	_, cancel, available := hub.Subscribe("three")
	defer cancel()
	if !available {
		t.Fatal("database reconnect did not restore subscriptions")
	}
}

func TestHubSlowSubscriberReconnectsWithoutBlockingOthers(t *testing.T) {
	hub := NewHub()
	slow, stopSlow, _ := hub.Subscribe("slow")
	fast, stopFast, _ := hub.Subscribe("fast")
	defer stopSlow()
	defer stopFast()
	for i := 0; i < 100; i++ {
		hub.Publish(Change{Topic: "catalog"})
		if _, open := <-fast; !open {
			t.Fatal("healthy subscriber was closed")
		}
	}
	for range slow {
	}
	hub.Publish(Change{Topic: "unknown"})
	select {
	case event := <-fast:
		t.Fatalf("unknown event delivered: %+v", event)
	default:
	}
}
