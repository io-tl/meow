package datastore

import "embed"

//go:embed migrations/schema.sql
var SchemaSQL string

//go:embed web/templates/*.html web/templates/partials/*.html
var TemplatesFS embed.FS

//go:embed all:web/static
var StaticFS embed.FS

//go:embed geoip/GeoLite2-City.mmdb
var EmbeddedGeoIPCity []byte

//go:embed geoip/GeoLite2-ASN.mmdb
var EmbeddedGeoIPASN []byte
