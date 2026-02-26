package main

import (
	"strings"

	"github.com/gin-gonic/gin"
)

func (api *API) dnsResolve(c *gin.Context) {
	query := strings.TrimSpace(c.Query("q"))
	if query == "" {
		c.JSON(400, gin.H{"error": "missing q parameter"})
		return
	}

	c.JSON(200, resolveDNS(query))
}
