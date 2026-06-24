package modules

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// UPnPModule implements the UPnP enrichment module
type UPnPModule struct {
	BaseModule
}

type UPnPService struct {
	ServiceType string `json:"service_type,omitempty"`
	ServiceID   string `json:"service_id,omitempty"`
	ControlURL  string `json:"control_url,omitempty"`
	EventSubURL string `json:"event_sub_url,omitempty"`
	SCPDURL     string `json:"scpd_url,omitempty"`
}

type UPnPDevice struct {
	DeviceType      string `json:"device_type,omitempty"`
	FriendlyName    string `json:"friendly_name,omitempty"`
	Manufacturer    string `json:"manufacturer,omitempty"`
	ModelName       string `json:"model_name,omitempty"`
	ModelNumber     string `json:"model_number,omitempty"`
	UDN             string `json:"udn,omitempty"`
	PresentationURL string `json:"presentation_url,omitempty"`
}

// UPnPResult represents the enriched UPnP data
type UPnPResult struct {
	Protocol         string            `json:"protocol"`
	Server           string            `json:"server,omitempty"`
	Location         string            `json:"location,omitempty"`
	ST               string            `json:"st,omitempty"`
	USN              string            `json:"usn,omitempty"`
	HTTPStatus       int               `json:"http_status,omitempty"`
	ContentType      string            `json:"content_type,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	BodySnippet      string            `json:"body_snippet,omitempty"`
	SpecVersion      string            `json:"spec_version,omitempty"`
	DeviceType       string            `json:"device_type,omitempty"`
	FriendlyName     string            `json:"friendly_name,omitempty"`
	Manufacturer     string            `json:"manufacturer,omitempty"`
	ManufacturerURL  string            `json:"manufacturer_url,omitempty"`
	ModelDescription string            `json:"model_description,omitempty"`
	ModelName        string            `json:"model_name,omitempty"`
	ModelNumber      string            `json:"model_number,omitempty"`
	ModelURL         string            `json:"model_url,omitempty"`
	SerialNumber     string            `json:"serial_number,omitempty"`
	UDNValue         string            `json:"udn_value,omitempty"`
	PresentationURL  string            `json:"presentation_url,omitempty"`
	Services         []UPnPService     `json:"services,omitempty"`
	Devices          []UPnPDevice      `json:"devices,omitempty"`
	Error            string            `json:"error,omitempty"`
}

type upnpRoot struct {
	SpecVersion struct {
		Major string `xml:"major"`
		Minor string `xml:"minor"`
	} `xml:"specVersion"`
	Device upnpXMLDevice `xml:"device"`
}

type upnpXMLDevice struct {
	DeviceType       string           `xml:"deviceType"`
	FriendlyName     string           `xml:"friendlyName"`
	Manufacturer     string           `xml:"manufacturer"`
	ManufacturerURL  string           `xml:"manufacturerURL"`
	ModelDescription string           `xml:"modelDescription"`
	ModelName        string           `xml:"modelName"`
	ModelNumber      string           `xml:"modelNumber"`
	ModelURL         string           `xml:"modelURL"`
	SerialNumber     string           `xml:"serialNumber"`
	UDN              string           `xml:"UDN"`
	PresentationURL  string           `xml:"presentationURL"`
	ServiceList      []upnpXMLService `xml:"serviceList>service"`
	DeviceList       []upnpXMLDevice  `xml:"deviceList>device"`
}

type upnpXMLService struct {
	ServiceType string `xml:"serviceType"`
	ServiceID   string `xml:"serviceId"`
	ControlURL  string `xml:"controlURL"`
	EventSubURL string `xml:"eventSubURL"`
	SCPDURL     string `xml:"SCPDURL"`
}

type upnpHTTPResult struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func init() {
	Register(&UPnPModule{
		BaseModule: NewBaseModule(
			"upnp",
			[]string{"ssdp"},
			true,
			10*time.Second,
		),
	})
}

func (m *UPnPModule) Scan(ip string, port int) (interface{}, error) {
	return scanUPnP(ip, port, m.DefaultTimeout())
}

// scanUPnP performs UPnP/SSDP enrichment.
func scanUPnP(ip string, port int, timeout time.Duration) (*UPnPResult, error) {
	result := &UPnPResult{
		Protocol: "upnp",
		Headers:  make(map[string]string),
	}

	if port == 1900 {
		if err := scanUPnPUDP(ip, port, timeout, result); err != nil && result.Error == "" {
			result.Error = err.Error()
		}
		if result.Location != "" {
			fetchUPnPDescription(result, result.Location, timeout)
		}
		return finalizeUPnPResult(result), nil
	}

	scanUPnPTCP(ip, port, timeout, result)

	udpTimeout := timeout / 8
	if udpTimeout <= 0 {
		udpTimeout = 500 * time.Millisecond
	}
	if udpTimeout > 1500*time.Millisecond {
		udpTimeout = 1500 * time.Millisecond
	}
	_ = scanUPnPUDP(ip, 1900, udpTimeout, result)

	if result.Location != "" {
		fetchUPnPDescription(result, result.Location, timeout)
	} else {
		tryUPnPDescriptionCandidates(ip, port, timeout, result)
	}

	return finalizeUPnPResult(result), nil
}

func scanUPnPTCP(ip string, port int, timeout time.Duration, result *UPnPResult) {
	httpResult, err := doUPnPHTTPRequest(fmt.Sprintf("http://%s:%d/", ip, port), http.MethodGet, timeout)
	if err != nil {
		if result.Error == "" {
			result.Error = err.Error()
		}
		return
	}

	result.HTTPStatus = httpResult.StatusCode
	result.ContentType = httpResult.Header.Get("Content-Type")
	mergeUPnPHeaders(result, httpResult.Header)
	result.BodySnippet = upnpBodySnippet(httpResult.Body)
}

func scanUPnPUDP(ip string, port int, timeout time.Duration, result *UPnPResult) error {
	conn, err := helpers.DialUDP(ip, port, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	msearch := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: upnp:rootdevice\r\n" +
		"\r\n"

	if _, err := conn.Write([]byte(msearch)); err != nil {
		return err
	}

	buffer := make([]byte, 8192)
	n, err := conn.Read(buffer)
	if err != nil {
		return err
	}

	parseUPnPHeaderBlock(string(buffer[:n]), result)
	return nil
}

func parseUPnPHeaderBlock(raw string, result *UPnPResult) {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	firstLine := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}
		if firstLine {
			firstLine = false
			if strings.HasPrefix(line, "HTTP/") && result.HTTPStatus == 0 {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					var status int
					fmt.Sscanf(fields[1], "%d", &status)
					result.HTTPStatus = status
				}
			}
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}
		switch key {
		case "server":
			result.Server = firstNonEmpty(result.Server, value)
		case "location":
			result.Location = firstNonEmpty(result.Location, value)
		case "st":
			result.ST = firstNonEmpty(result.ST, value)
		case "usn":
			result.USN = firstNonEmpty(result.USN, value)
		case "content-type":
			result.ContentType = firstNonEmpty(result.ContentType, value)
		}
		if result.Headers == nil {
			result.Headers = make(map[string]string)
		}
		if _, ok := result.Headers[key]; !ok {
			result.Headers[key] = value
		}
	}
}

func tryUPnPDescriptionCandidates(ip string, port int, timeout time.Duration, result *UPnPResult) {
	paths := []string{
		"/rootDesc.xml",
		"/rootdesc.xml",
		"/description.xml",
		"/device.xml",
		"/root.xml",
		"/igd.xml",
	}

	for _, path := range paths {
		location := fmt.Sprintf("http://%s:%d%s", ip, port, path)
		if fetchUPnPDescription(result, location, timeout) {
			if result.Location == "" {
				result.Location = location
			}
			return
		}
	}
}

func fetchUPnPDescription(result *UPnPResult, location string, timeout time.Duration) bool {
	location = normalizeUPnPLocation(location, location)
	if location == "" {
		return false
	}

	httpResult, err := doUPnPHTTPRequest(location, http.MethodGet, timeout)
	if err != nil {
		return false
	}
	if !looksLikeUPnPXML(httpResult.Body, httpResult.Header.Get("Content-Type")) {
		if result.HTTPStatus == 0 {
			result.HTTPStatus = httpResult.StatusCode
		}
		mergeUPnPHeaders(result, httpResult.Header)
		if result.BodySnippet == "" {
			result.BodySnippet = upnpBodySnippet(httpResult.Body)
		}
		return false
	}

	var root upnpRoot
	if err := xml.Unmarshal(httpResult.Body, &root); err != nil {
		return false
	}

	result.Location = location
	result.HTTPStatus = httpResult.StatusCode
	result.ContentType = firstNonEmpty(result.ContentType, httpResult.Header.Get("Content-Type"))
	mergeUPnPHeaders(result, httpResult.Header)
	result.BodySnippet = upnpBodySnippet(httpResult.Body)
	if root.SpecVersion.Major != "" || root.SpecVersion.Minor != "" {
		result.SpecVersion = fmt.Sprintf("%s.%s", root.SpecVersion.Major, root.SpecVersion.Minor)
	}
	applyUPnPDevice(result, root.Device)
	return true
}

func applyUPnPDevice(result *UPnPResult, device upnpXMLDevice) {
	if device.DeviceType != "" && result.DeviceType == "" {
		result.DeviceType = device.DeviceType
		result.FriendlyName = device.FriendlyName
		result.Manufacturer = device.Manufacturer
		result.ManufacturerURL = device.ManufacturerURL
		result.ModelDescription = device.ModelDescription
		result.ModelName = device.ModelName
		result.ModelNumber = device.ModelNumber
		result.ModelURL = device.ModelURL
		result.SerialNumber = device.SerialNumber
		result.UDNValue = device.UDN
		result.PresentationURL = device.PresentationURL
	}

	result.Devices = append(result.Devices, UPnPDevice{
		DeviceType:      device.DeviceType,
		FriendlyName:    device.FriendlyName,
		Manufacturer:    device.Manufacturer,
		ModelName:       device.ModelName,
		ModelNumber:     device.ModelNumber,
		UDN:             device.UDN,
		PresentationURL: device.PresentationURL,
	})

	for _, service := range device.ServiceList {
		result.Services = append(result.Services, UPnPService{
			ServiceType: service.ServiceType,
			ServiceID:   service.ServiceID,
			ControlURL:  service.ControlURL,
			EventSubURL: service.EventSubURL,
			SCPDURL:     service.SCPDURL,
		})
	}

	for _, child := range device.DeviceList {
		applyUPnPDevice(result, child)
	}
}

func doUPnPHTTPRequest(rawURL, method string, timeout time.Duration) (*upnpHTTPResult, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "grabber/1.0")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, err
	}

	return &upnpHTTPResult{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
	}, nil
}

func looksLikeUPnPXML(body []byte, contentType string) bool {
	if strings.Contains(strings.ToLower(contentType), "xml") {
		return true
	}
	trimmed := strings.TrimSpace(string(body))
	return strings.HasPrefix(trimmed, "<?xml") || strings.Contains(trimmed, "<root")
}

func mergeUPnPHeaders(result *UPnPResult, header http.Header) {
	if result.Headers == nil {
		result.Headers = make(map[string]string)
	}
	for key, values := range header {
		if len(values) == 0 {
			continue
		}
		lowerKey := strings.ToLower(key)
		if _, ok := result.Headers[lowerKey]; !ok {
			result.Headers[lowerKey] = strings.Join(values, ", ")
		}
	}
	result.Server = firstNonEmpty(result.Server, header.Get("Server"))
	result.Location = firstNonEmpty(result.Location, header.Get("Location"))
	result.ST = firstNonEmpty(result.ST, header.Get("ST"))
	result.USN = firstNonEmpty(result.USN, header.Get("USN"))
}

func upnpBodySnippet(body []byte) string {
	snippet := strings.TrimSpace(helpers.CleanString(string(body)))
	if len(snippet) > 512 {
		snippet = snippet[:512]
	}
	return snippet
}

func finalizeUPnPResult(result *UPnPResult) *UPnPResult {
	if len(result.Headers) == 0 {
		result.Headers = nil
	}
	if len(result.Services) == 0 {
		result.Services = nil
	}
	if len(result.Devices) == 0 {
		result.Devices = nil
	}
	if result.Error != "" && (result.Server != "" || result.Location != "" || result.HTTPStatus != 0 || result.DeviceType != "" || result.FriendlyName != "") {
		result.Error = ""
	}
	return result
}

func normalizeUPnPLocation(baseURL, rawLocation string) string {
	if rawLocation == "" {
		return ""
	}
	locationURL, err := url.Parse(rawLocation)
	if err != nil {
		return ""
	}
	if locationURL.IsAbs() {
		return locationURL.String()
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	return base.ResolveReference(locationURL).String()
}
