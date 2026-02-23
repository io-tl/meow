package main

import (
	"net"
	"strings"
)

// privateRange describes an RFC private/reserved IP range.
type privateRange struct {
	network *net.IPNet
	label   string // e.g. "RFC 1918 - 192.168.0.0/16"
}

var privateRanges []privateRange

func init() {
	for _, cidr := range []struct {
		cidr  string
		label string
	}{
		{"10.0.0.0/8", "RFC 1918 - 10.0.0.0/8"},
		{"172.16.0.0/12", "RFC 1918 - 172.16.0.0/12"},
		{"192.168.0.0/16", "RFC 1918 - 192.168.0.0/16"},
		{"127.0.0.0/8", "Loopback - 127.0.0.0/8"},
		{"169.254.0.0/16", "Link-Local - 169.254.0.0/16"},
		{"::1/128", "Loopback - ::1"},
		{"fc00::/7", "RFC 4193 - fc00::/7"},
		{"fe80::/10", "Link-Local - fe80::/10"},
	} {
		_, network, _ := net.ParseCIDR(cidr.cidr)
		privateRanges = append(privateRanges, privateRange{network: network, label: cidr.label})
	}
}

// isPrivateIP checks if an IP belongs to a private/reserved range and returns its label.
func isPrivateIP(ip net.IP) (string, bool) {
	for _, r := range privateRanges {
		if r.network.Contains(ip) {
			return r.label, true
		}
	}
	return "", false
}

// enrichHostWithGeoIP adds geolocation, ASN, and cloud/CDN/WAF data to host information
func (c *Consumer) enrichHostWithGeoIP(ip string) (countryCode, countryName, city, timezone *string, asn *int, asOrg *string, isp *string, cloudProvider, cloudRegion, cloudType *string) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return
	}

	// Private/reserved IPs: fill with meaningful values instead of leaving NULL
	if label, ok := isPrivateIP(parsedIP); ok {
		cc := "XX"
		cn := label
		a := 0
		countryCode = &cc
		countryName = &cn
		asn = &a
		return
	}

	// Get city geolocation data
	if c.geoipCity != nil {
		if cityRecord, err := c.geoipCity.City(parsedIP); err == nil {
			if countryNameStr := cityRecord.Country.Names["en"]; countryNameStr != "" {
				countryName = &countryNameStr
			}
			if isoCode := cityRecord.Country.IsoCode; isoCode != "" {
				countryCode = &isoCode
			}
			if cityNameStr := cityRecord.City.Names["en"]; cityNameStr != "" {
				city = &cityNameStr
			}
			if tz := cityRecord.Location.TimeZone; tz != "" {
				timezone = &tz
			}
		}
	}

	// Get ASN data
	if c.geoipASN != nil {
		if asnRecord, err := c.geoipASN.ASN(parsedIP); err == nil {
			asnInt := int(asnRecord.AutonomousSystemNumber)
			asn = &asnInt
			if asnRecord.AutonomousSystemOrganization != "" {
				asOrg = &asnRecord.AutonomousSystemOrganization
			}
			isp = &asnRecord.AutonomousSystemOrganization
		}
	}

	// Detect cloud/CDN/WAF via cdncheck (IP range lookup)
	if c.cdnCheck != nil {
		if matched, provider, itemType, err := c.cdnCheck.Check(parsedIP); err == nil && matched {
			cloudProvider = &provider
			cloudType = &itemType
		}
	}

	// Fallback: detect provider from ASN org name (cdncheck doesn't cover all providers)
	if cloudProvider == nil && asOrg != nil {
		if provider, itemType := detectProviderFromASN(*asOrg); provider != "" {
			cloudProvider = &provider
			cloudType = &itemType
		}
	}

	// Detect cloud region from ASN org (only for cloud providers)
	if cloudProvider != nil && asOrg != nil && (cloudType == nil || *cloudType == "cloud") {
		if region := detectCloudRegion(*asOrg); region != "" {
			cloudRegion = &region
		}
	}

	return
}

// asnEntry maps an ASN org keyword to a provider name and type.
type asnEntry struct {
	provider  string
	entryType string // "cloud", "cdn", "waf"
}

// detectProviderFromASN identifies cloud/CDN/WAF provider from AS organization name.
// Used as fallback when cdncheck doesn't have the provider in its IP ranges.
func detectProviderFromASN(asOrg string) (provider, itemType string) {
	asOrg = strings.ToLower(asOrg)

	providers := []struct {
		keyword string
		asnEntry
	}{
		// ── Hyperscalers ──
		{"amazon", asnEntry{"aws", "cloud"}},
		{"google", asnEntry{"gcp", "cloud"}},
		{"microsoft", asnEntry{"azure", "cloud"}},
		{"alibaba", asnEntry{"alibaba", "cloud"}},
		{"tencent", asnEntry{"tencent", "cloud"}},
		{"huawei", asnEntry{"huawei", "cloud"}},
		{"oracle", asnEntry{"oracle", "cloud"}},
		{"ibm", asnEntry{"ibm", "cloud"}},
		{"salesforce", asnEntry{"salesforce", "cloud"}},

		// ── Major cloud / VPS ──
		{"digitalocean", asnEntry{"digitalocean", "cloud"}},
		{"hetzner", asnEntry{"hetzner", "cloud"}},
		{"ovh", asnEntry{"ovh", "cloud"}},
		{"vultr", asnEntry{"vultr", "cloud"}},
		{"choopa", asnEntry{"vultr", "cloud"}},
		{"linode", asnEntry{"linode", "cloud"}},
		{"scaleway", asnEntry{"scaleway", "cloud"}},
		{"upcloud", asnEntry{"upcloud", "cloud"}},
		{"kamatera", asnEntry{"kamatera", "cloud"}},
		{"cherryservers", asnEntry{"cherryservers", "cloud"}},
		{"leaseweb", asnEntry{"leaseweb", "cloud"}},
		{"contabo", asnEntry{"contabo", "cloud"}},
		{"ionos", asnEntry{"ionos", "cloud"}},
		{"strato", asnEntry{"strato", "cloud"}},
		{"netcup", asnEntry{"netcup", "cloud"}},
		{"hostinger", asnEntry{"hostinger", "cloud"}},
		{"hostwinds", asnEntry{"hostwinds", "cloud"}},
		{"interserver", asnEntry{"interserver", "cloud"}},
		{"dreamhost", asnEntry{"dreamhost", "cloud"}},
		{"rackspace", asnEntry{"rackspace", "cloud"}},
		{"softlayer", asnEntry{"softlayer", "cloud"}},
		{"equinix", asnEntry{"equinix", "cloud"}},
		{"packet", asnEntry{"equinix", "cloud"}},
		{"phoenixnap", asnEntry{"phoenixnap", "cloud"}},
		{"quadranet", asnEntry{"quadranet", "cloud"}},

		// ── Regional / Telecom cloud ──
		{"yandex", asnEntry{"yandex", "cloud"}},
		{"selectel", asnEntry{"selectel", "cloud"}},
		{"naver", asnEntry{"naver", "cloud"}},
		{"kakao", asnEntry{"kakao", "cloud"}},
		{"sakura", asnEntry{"sakura", "cloud"}},
		{"conoha", asnEntry{"conoha", "cloud"}},
		{"aruba", asnEntry{"aruba", "cloud"}},
		{"infomaniak", asnEntry{"infomaniak", "cloud"}},
		{"exoscale", asnEntry{"exoscale", "cloud"}},
		{"cloudsigma", asnEntry{"cloudsigma", "cloud"}},
		{"gcore", asnEntry{"gcore", "cloud"}},
		{"servers.com", asnEntry{"servers.com", "cloud"}},
		{"maxihost", asnEntry{"maxihost", "cloud"}},
		{"hostkey", asnEntry{"hostkey", "cloud"}},

		// ── Hosting / dedicated ──
		{"godaddy", asnEntry{"godaddy", "cloud"}},
		{"bluehost", asnEntry{"bluehost", "cloud"}},
		{"namecheap", asnEntry{"namecheap", "cloud"}},
		{"liquidweb", asnEntry{"liquidweb", "cloud"}},
		{"siteground", asnEntry{"siteground", "cloud"}},
		{"a2 hosting", asnEntry{"a2hosting", "cloud"}},
		{"inmotion", asnEntry{"inmotion", "cloud"}},
		{"greengeeks", asnEntry{"greengeeks", "cloud"}},
		{"wpengine", asnEntry{"wpengine", "cloud"}},
		{"kinsta", asnEntry{"kinsta", "cloud"}},
		{"flywheel", asnEntry{"flywheel", "cloud"}},

		// ── CDN ──
		{"cloudflare", asnEntry{"cloudflare", "cdn"}},
		{"fastly", asnEntry{"fastly", "cdn"}},
		{"akamai", asnEntry{"akamai", "cdn"}},
		{"edgecast", asnEntry{"edgecast", "cdn"}},
		{"verizon digital", asnEntry{"edgecast", "cdn"}},
		{"limelight", asnEntry{"limelight", "cdn"}},
		{"stackpath", asnEntry{"stackpath", "cdn"}},
		{"highwinds", asnEntry{"stackpath", "cdn"}},
		{"maxcdn", asnEntry{"stackpath", "cdn"}},
		{"cloudfront", asnEntry{"cloudfront", "cdn"}},
		{"keycdn", asnEntry{"keycdn", "cdn"}},
		{"bunny", asnEntry{"bunnycdn", "cdn"}},
		{"cdn77", asnEntry{"cdn77", "cdn"}},
		{"beluga", asnEntry{"belugacdn", "cdn"}},
		{"cachefly", asnEntry{"cachefly", "cdn"}},
		{"chinacache", asnEntry{"chinacache", "cdn"}},
		{"cdnetworks", asnEntry{"cdnetworks", "cdn"}},
		{"quantil", asnEntry{"cdnetworks", "cdn"}},
		{"azion", asnEntry{"azion", "cdn"}},
		{"imperva", asnEntry{"imperva", "cdn"}},
		{"incapsula", asnEntry{"imperva", "cdn"}},
		{"lumen", asnEntry{"lumen", "cdn"}},
		{"centurylink", asnEntry{"lumen", "cdn"}},
		{"level3", asnEntry{"lumen", "cdn"}},
		{"section.io", asnEntry{"section", "cdn"}},
		{"netlify", asnEntry{"netlify", "cdn"}},
		{"vercel", asnEntry{"vercel", "cdn"}},
		{"fly.io", asnEntry{"flyio", "cdn"}},
		{"render", asnEntry{"render", "cdn"}},
		{"heroku", asnEntry{"heroku", "cdn"}},
		{"jsdelivr", asnEntry{"jsdelivr", "cdn"}},
		{"turbobytes", asnEntry{"turbobytes", "cdn"}},
		{"medianova", asnEntry{"medianova", "cdn"}},
		{"arvancloud", asnEntry{"arvancloud", "cdn"}},
		{"transparentcdn", asnEntry{"transparentcdn", "cdn"}},
		{"metacdn", asnEntry{"metacdn", "cdn"}},
		{"swarmify", asnEntry{"swarmify", "cdn"}},
		{"reflected networks", asnEntry{"reflected", "cdn"}},
		{"voxility", asnEntry{"voxility", "cdn"}},
		{"webscale", asnEntry{"webscale", "cdn"}},
		{"onapp", asnEntry{"onapp", "cdn"}},
		{"google cloud cdn", asnEntry{"gcp-cdn", "cdn"}},
		{"microsoft cdn", asnEntry{"azure-cdn", "cdn"}},
		{"alibaba cdn", asnEntry{"alibaba-cdn", "cdn"}},
		{"telia carrier", asnEntry{"telia", "cdn"}},
		{"ntt comm", asnEntry{"ntt", "cdn"}},
		{"zenlayer", asnEntry{"zenlayer", "cdn"}},
		{"g-core", asnEntry{"gcore", "cdn"}},
		{"ddos-guard", asnEntry{"ddosguard", "cdn"}},

		// ── WAF / DDoS Protection ──
		{"sucuri", asnEntry{"sucuri", "waf"}},
		{"barracuda", asnEntry{"barracuda", "waf"}},
		{"f5 ", asnEntry{"f5", "waf"}},
		{"fortinet", asnEntry{"fortinet", "waf"}},
		{"radware", asnEntry{"radware", "waf"}},
		{"wallarm", asnEntry{"wallarm", "waf"}},
		{"reblaze", asnEntry{"reblaze", "waf"}},
		{"wordfence", asnEntry{"wordfence", "waf"}},
		{"perimeterx", asnEntry{"perimeterx", "waf"}},
		{"human security", asnEntry{"humansecurity", "waf"}},
		{"signal sciences", asnEntry{"signalsciences", "waf"}},
		{"sqreen", asnEntry{"sqreen", "waf"}},
		{"prophaze", asnEntry{"prophaze", "waf"}},
		{"link11", asnEntry{"link11", "waf"}},
		{"myra security", asnEntry{"myra", "waf"}},
		{"neustar", asnEntry{"neustar", "waf"}},
		{"qrator", asnEntry{"qrator", "waf"}},
		{"stormwall", asnEntry{"stormwall", "waf"}},
		{"path.net", asnEntry{"pathnet", "waf"}},
		{"ddos-guard", asnEntry{"ddosguard", "waf"}},
	}

	for _, p := range providers {
		if strings.Contains(asOrg, p.keyword) {
			return p.provider, p.entryType
		}
	}

	return "", ""
}

// detectCloudRegion extracts cloud region from AS organization
func detectCloudRegion(asOrg string) string {
	asOrg = strings.ToLower(asOrg)

	// AWS regions
	if strings.Contains(asOrg, "aws") {
		if strings.Contains(asOrg, "ireland") || strings.Contains(asOrg, "dublin") {
			return "eu-west-1"
		}
		if strings.Contains(asOrg, "frankfurt") {
			return "eu-central-1"
		}
		if strings.Contains(asOrg, "paris") {
			return "eu-west-3"
		}
		if strings.Contains(asOrg, "london") {
			return "eu-west-2"
		}
		if strings.Contains(asOrg, "virginia") {
			return "us-east-1"
		}
		if strings.Contains(asOrg, "california") {
			return "us-west-1"
		}
		if strings.Contains(asOrg, "oregon") {
			return "us-west-2"
		}
	}

	// GCP regions
	if strings.Contains(asOrg, "google") {
		if strings.Contains(asOrg, "europe-west1") {
			return "europe-west1"
		}
		if strings.Contains(asOrg, "europe-west2") {
			return "europe-west2"
		}
		if strings.Contains(asOrg, "us-central1") {
			return "us-central1"
		}
		if strings.Contains(asOrg, "us-east1") {
			return "us-east1"
		}
	}

	return ""
}
