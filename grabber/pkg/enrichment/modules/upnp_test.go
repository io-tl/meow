package modules

import "testing"

func TestParseUPnPHeaderBlock(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nSERVER: Linux/3.18.20, UPnP/1.0, Portable SDK for UPnP devices/1.6.18\r\nLOCATION: http://192.0.2.1:12345/rootDesc.xml\r\nST: upnp:rootdevice\r\nUSN: uuid:device-1::upnp:rootdevice\r\n\r\n"
	result := &UPnPResult{Protocol: "upnp", Headers: make(map[string]string)}

	parseUPnPHeaderBlock(raw, result)

	if result.HTTPStatus != 200 {
		t.Fatalf("HTTPStatus = %d", result.HTTPStatus)
	}
	if result.Server == "" {
		t.Fatal("Server is empty")
	}
	if result.Location != "http://192.0.2.1:12345/rootDesc.xml" {
		t.Fatalf("Location = %q", result.Location)
	}
	if result.ST != "upnp:rootdevice" {
		t.Fatalf("ST = %q", result.ST)
	}
	if result.USN != "uuid:device-1::upnp:rootdevice" {
		t.Fatalf("USN = %q", result.USN)
	}
}

func TestApplyUPnPDevice(t *testing.T) {
	result := &UPnPResult{Protocol: "upnp"}
	device := upnpXMLDevice{
		DeviceType:      "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		FriendlyName:    "Test Gateway",
		Manufacturer:    "Acme",
		ModelName:       "Router 1",
		ModelNumber:     "v1",
		UDN:             "uuid:device-1",
		PresentationURL: "/index.html",
		ServiceList: []upnpXMLService{
			{
				ServiceType: "urn:schemas-upnp-org:service:WANIPConnection:1",
				ServiceID:   "urn:upnp-org:serviceId:WANIPConn1",
				ControlURL:  "/control",
				EventSubURL: "/event",
				SCPDURL:     "/scpd.xml",
			},
		},
		DeviceList: []upnpXMLDevice{
			{
				DeviceType:   "urn:schemas-upnp-org:device:WANDevice:1",
				FriendlyName: "WAN Device",
			},
		},
	}

	applyUPnPDevice(result, device)

	if result.DeviceType != "urn:schemas-upnp-org:device:InternetGatewayDevice:1" {
		t.Fatalf("DeviceType = %q", result.DeviceType)
	}
	if result.FriendlyName != "Test Gateway" {
		t.Fatalf("FriendlyName = %q", result.FriendlyName)
	}
	if len(result.Services) != 1 {
		t.Fatalf("len(Services) = %d", len(result.Services))
	}
	if len(result.Devices) != 2 {
		t.Fatalf("len(Devices) = %d", len(result.Devices))
	}
}
