package main

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RecentEvent represents a recent pipeline event for the UI feed
type RecentEvent struct {
	Type    string `json:"type"`    // "open", "fingerprinted", "enriched"
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Product string `json:"product,omitempty"`
	At      int64  `json:"at"` // unix timestamp
}

// EventFeed is a thread-safe ring buffer of recent events
type EventFeed struct {
	mu    sync.Mutex
	items []RecentEvent
	max   int
}

func NewEventFeed(max int) *EventFeed {
	return &EventFeed{
		items: make([]RecentEvent, 0, max),
		max:   max,
	}
}

func (f *EventFeed) Push(e RecentEvent) {
	if e.At == 0 {
		e.At = time.Now().Unix()
	}
	f.mu.Lock()
	if len(f.items) >= f.max {
		f.items = f.items[1:]
	}
	f.items = append(f.items, e)
	f.mu.Unlock()
}

// Recent returns the last n events, newest first
func (f *EventFeed) Recent(n int) []RecentEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	l := len(f.items)
	if n > l {
		n = l
	}
	out := make([]RecentEvent, n)
	for i := 0; i < n; i++ {
		out[i] = f.items[l-1-i]
	}
	return out
}

func (a *API) getRecentEvents(c *gin.Context) {
	events := a.eventFeed.Recent(30)
	if events == nil {
		events = make([]RecentEvent, 0)
	}
	c.JSON(http.StatusOK, gin.H{"events": events})
}
