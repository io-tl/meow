package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type cachedJSONResponse struct {
	body      []byte
	expiresAt time.Time
}

type apiResponseCache struct {
	mu      sync.RWMutex
	entries map[string]cachedJSONResponse
}

func newAPIResponseCache() *apiResponseCache {
	return &apiResponseCache{
		entries: make(map[string]cachedJSONResponse),
	}
}

func (c *apiResponseCache) get(key string) ([]byte, bool) {
	now := time.Now()

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if now.After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, false
	}
	return entry.body, true
}

func (c *apiResponseCache) set(key string, body []byte, ttl time.Duration) {
	c.mu.Lock()
	c.entries[key] = cachedJSONResponse{
		body:      body,
		expiresAt: time.Now().Add(ttl),
	}
	c.mu.Unlock()
}

func (api *API) writeCachedJSON(c *gin.Context, key string) bool {
	if api.responseCache == nil {
		return false
	}
	body, ok := api.responseCache.get(key)
	if !ok {
		return false
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", body)
	return true
}

func (api *API) cacheAndWriteJSON(c *gin.Context, key string, ttl time.Duration, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if api.responseCache != nil {
		api.responseCache.set(key, body, ttl)
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", body)
}
