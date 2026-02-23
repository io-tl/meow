package main

import (
	"net"
	"strings"

	"github.com/gin-gonic/gin"
)

func (api *API) dnsResolve(c *gin.Context) {
	query := strings.TrimSpace(c.Query("q"))
	if query == "" {
		c.JSON(400, gin.H{"error": "missing q parameter"})
		return
	}

	result := gin.H{"query": query}

	// A records
	ips, err := net.LookupHost(query)
	if err == nil {
		var ipv4, ipv6 []string
		for _, ip := range ips {
			if strings.Contains(ip, ":") {
				ipv6 = append(ipv6, ip)
			} else {
				ipv4 = append(ipv4, ip)
			}
		}
		if ipv4 != nil {
			result["a"] = ipv4
		}
		if ipv6 != nil {
			result["aaaa"] = ipv6
		}
	}

	// CNAME
	cname, err := net.LookupCNAME(query)
	if err == nil && cname != "" && strings.TrimSuffix(cname, ".") != query {
		result["cname"] = strings.TrimSuffix(cname, ".")
	}

	// MX
	mxs, err := net.LookupMX(query)
	if err == nil && len(mxs) > 0 {
		mxList := make([]gin.H, 0, len(mxs))
		for _, mx := range mxs {
			mxList = append(mxList, gin.H{
				"host": strings.TrimSuffix(mx.Host, "."),
				"pref": mx.Pref,
			})
		}
		result["mx"] = mxList
	}

	// NS
	nss, err := net.LookupNS(query)
	if err == nil && len(nss) > 0 {
		nsList := make([]string, 0, len(nss))
		for _, ns := range nss {
			nsList = append(nsList, strings.TrimSuffix(ns.Host, "."))
		}
		result["ns"] = nsList
	}

	// TXT
	txts, err := net.LookupTXT(query)
	if err == nil && len(txts) > 0 {
		result["txt"] = txts
	}

	// Reverse lookup if query looks like an IP
	if ip := net.ParseIP(query); ip != nil {
		names, err := net.LookupAddr(query)
		if err == nil && len(names) > 0 {
			ptrs := make([]string, 0, len(names))
			for _, n := range names {
				ptrs = append(ptrs, strings.TrimSuffix(n, "."))
			}
			result["ptr"] = ptrs
		}
	}

	c.JSON(200, result)
}
