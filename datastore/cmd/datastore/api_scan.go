package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (a *API) getScanners(c *gin.Context) {
	scanners := a.scanTracker.GetActiveScanners()
	if scanners == nil {
		scanners = make([]*ScannerNode, 0)
	}
	c.JSON(http.StatusOK, gin.H{
		"count":    len(scanners),
		"scanners": scanners,
	})
}

type submitScanRequest struct {
	Target    string `json:"target" binding:"required"`
	Ports     string `json:"ports" binding:"required"`
	RateLimit int    `json:"rate_limit,omitempty"`
}

func (a *API) submitScan(c *gin.Context) {
	var req submitScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target and ports are required"})
		return
	}

	if !a.scanTracker.HasActiveScanners() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "no active scanners available"})
		return
	}

	scanReq := ScanRequest{
		RequestID: uuid.New().String(),
		Target:    req.Target,
		Ports:     req.Ports,
		RateLimit: req.RateLimit,
		Timestamp: time.Now().Unix(),
	}

	data, err := json.Marshal(scanReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal scan request"})
		return
	}

	if err := a.nc.Publish(TopicScanRequest, data); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to publish scan request"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"request_id": scanReq.RequestID,
		"message":    "scan request submitted",
	})
}
