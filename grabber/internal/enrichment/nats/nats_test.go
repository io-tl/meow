package nats

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"meow/grabber/pkg/enrichment/types"

	natsgo "github.com/nats-io/nats.go"
	natsserver "github.com/nats-io/nats-server/v2/server"
)

// startTestNATS starts an embedded NATS server and returns a connected client.
func startTestNATS(t *testing.T) *natsgo.Conn {
	t.Helper()
	opts := &natsserver.Options{Port: -1}
	s, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server not ready")
	}
	t.Cleanup(func() { s.Shutdown() })

	nc, err := natsgo.Connect(s.ClientURL())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { nc.Close() })
	return nc
}

func TestNewConsumer(t *testing.T) {
	nc := startTestNATS(t)
	c, err := NewConsumer(nc, []string{"test.subject"}, func(req *types.EnrichmentRequest) {})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}
	if len(c.subjects) != 1 || c.subjects[0] != "test.subject" {
		t.Errorf("subjects = %v", c.subjects)
	}
}

func TestConsumer_StartAndReceive(t *testing.T) {
	nc := startTestNATS(t)

	var received *types.EnrichmentRequest
	var mu sync.Mutex
	done := make(chan struct{})

	c, _ := NewConsumer(nc, []string{"test.enrich"}, func(req *types.EnrichmentRequest) {
		mu.Lock()
		received = req
		mu.Unlock()
		close(done)
	})

	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()

	// Publish a valid message
	req := &types.EnrichmentRequest{IP: "1.2.3.4", Port: 80, Service: "http"}
	data, _ := json.Marshal(req)
	nc.Publish("test.enrich", data)
	nc.Flush()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for message")
	}

	mu.Lock()
	defer mu.Unlock()
	if received == nil {
		t.Fatal("received is nil")
	}
	if received.IP != "1.2.3.4" {
		t.Errorf("IP = %q", received.IP)
	}
	if received.Port != 80 {
		t.Errorf("Port = %d", received.Port)
	}
	if received.Service != "http" {
		t.Errorf("Service = %q", received.Service)
	}
}

func TestConsumer_InvalidJSON(t *testing.T) {
	nc := startTestNATS(t)

	called := false
	c, _ := NewConsumer(nc, []string{"test.bad"}, func(req *types.EnrichmentRequest) {
		called = true
	})

	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()

	// Publish invalid JSON
	nc.Publish("test.bad", []byte("not json"))
	nc.Flush()
	time.Sleep(200 * time.Millisecond)

	if called {
		t.Error("handler should not be called for invalid JSON")
	}
}

func TestConsumer_Stop(t *testing.T) {
	nc := startTestNATS(t)
	c, _ := NewConsumer(nc, []string{"test.stop"}, func(req *types.EnrichmentRequest) {})
	c.Start()

	err := c.Stop()
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestNewPublisher(t *testing.T) {
	nc := startTestNATS(t)
	p := NewPublisher(nc, "test.out")
	if p.subject != "test.out" {
		t.Errorf("subject = %q", p.subject)
	}
}

func TestPublisher_Publish(t *testing.T) {
	nc := startTestNATS(t)

	// Subscribe to receive the published message
	var received []byte
	done := make(chan struct{})
	nc.Subscribe("test.pub", func(msg *natsgo.Msg) {
		received = msg.Data
		close(done)
	})

	p := NewPublisher(nc, "test.pub")
	result := types.NewEnrichmentResult("1.2.3.4", 80, "http", "", map[string]string{"key": "val"})
	err := p.Publish(result)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	nc.Flush()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	var decoded types.EnrichmentResult
	if err := json.Unmarshal(received, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.IP != "1.2.3.4" {
		t.Errorf("IP = %q", decoded.IP)
	}
}

func TestPublishWithRetry_Success(t *testing.T) {
	nc := startTestNATS(t)
	p := NewPublisher(nc, "test.retry")

	result := types.NewEnrichmentResult("1.2.3.4", 80, "http", "", nil)
	err := p.PublishWithRetry(result, 3)
	if err != nil {
		t.Fatalf("PublishWithRetry: %v", err)
	}
}

func TestPublishWithRetry_AllFail(t *testing.T) {
	nc := startTestNATS(t)
	nc.Close() // close connection to force errors

	p := NewPublisher(nc, "test.fail")
	result := types.NewEnrichmentResult("1.2.3.4", 80, "http", "", nil)
	err := p.PublishWithRetry(result, 2)
	if err == nil {
		t.Error("expected error for closed connection")
	}
}

func TestQueueGroup_LoadBalanced(t *testing.T) {
	nc := startTestNATS(t)

	var count1, count2 int
	var mu sync.Mutex
	done := make(chan struct{})

	c1, _ := NewConsumer(nc, []string{"test.queue"}, func(req *types.EnrichmentRequest) {
		mu.Lock()
		count1++
		mu.Unlock()
	})
	c2, _ := NewConsumer(nc, []string{"test.queue"}, func(req *types.EnrichmentRequest) {
		mu.Lock()
		count2++
		mu.Unlock()
	})

	c1.Start()
	c2.Start()
	defer c1.Stop()
	defer c2.Stop()

	// Publish multiple messages
	for i := 0; i < 10; i++ {
		req := &types.EnrichmentRequest{IP: "1.2.3.4", Port: i, Service: "http"}
		data, _ := json.Marshal(req)
		nc.Publish("test.queue", data)
	}
	nc.Flush()

	// Wait for processing
	go func() {
		time.Sleep(2 * time.Second)
		close(done)
	}()
	<-done

	mu.Lock()
	total := count1 + count2
	mu.Unlock()

	if total != 10 {
		t.Errorf("total processed = %d, want 10", total)
	}
}
