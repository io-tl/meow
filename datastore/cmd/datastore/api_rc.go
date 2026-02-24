package main

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

// getShellRC serves a bash script that exposes all meow API functions
// via a single `mw` command with subcommands.
// Usage: . <(curl -s http://host:port/api/rc)
//
//	eval "$(curl -s http://host:port/api/rc)"
func (api *API) getShellRC(c *gin.Context) {
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, c.Request.Host)
	apiKey := c.Query("key")

	script := strings.ReplaceAll(shellRC, "{{MEOW_URL}}", baseURL)
	script = strings.ReplaceAll(script, "{{MEOW_KEY}}", apiKey)

	c.Data(200, "text/plain; charset=utf-8", []byte(script))
}

const shellRC = `#!/bin/bash
# meow shell rc — network scanner CLI
# Source: . <(curl -s http://host:port/api/rc)

export MEOW_URL="${MEOW_URL:-{{MEOW_URL}}}"
export MEOW_KEY="${MEOW_KEY:-{{MEOW_KEY}}}"

# ── internals ────────────────────────────────────────────────────────────────

_mw_get() {
    local ep="$1"; shift
    local url="${MEOW_URL}/api${ep}"
    local -a h=(-s -f --connect-timeout 5)
    [[ -n "$MEOW_KEY" ]] && h+=(-H "X-API-Key: $MEOW_KEY")
    curl "${h[@]}" "$url" "$@"
}

_mw_post() {
    local ep="$1"; shift
    local url="${MEOW_URL}/api${ep}"
    local -a h=(-s -f --connect-timeout 5 -X POST -H "Content-Type: application/json")
    [[ -n "$MEOW_KEY" ]] && h+=(-H "X-API-Key: $MEOW_KEY")
    curl "${h[@]}" "$url" "$@"
}

_mw_raw() { jq -r "$@"; }
_mw_json() { if [[ -t 1 ]]; then jq -C "$@"; else jq "$@"; fi; }

# ANSI helpers
_mw_b='\033[1m'    # bold
_mw_d='\033[2m'    # dim
_mw_c='\033[36m'   # cyan
_mw_g='\033[32m'   # green
_mw_y='\033[33m'   # yellow
_mw_r='\033[31m'   # red
_mw_m='\033[35m'   # magenta
_mw_w='\033[97m'   # white
_mw_0='\033[0m'    # reset

_mw_hdr() { [[ -t 1 ]] && printf "${_mw_b}${_mw_c}%s${_mw_0}\n" "$1" || printf "%s\n" "$1"; }
_mw_dim() { [[ -t 1 ]] && printf "${_mw_d}%s${_mw_0}\n" "$1" || printf "%s\n" "$1"; }
_mw_err() { printf "${_mw_r}error:${_mw_0} %s\n" "$1" >&2; }

# ── main dispatcher ──────────────────────────────────────────────────────────

mw() {
    # Parse global flags before the command
    local _mw_global_limit="" _mw_global_json=0
    while [[ "${1:-}" == -* ]]; do
        case "$1" in
            -n|--limit) _mw_global_limit="$2"; shift 2 ;;
            --json)     _mw_global_json=1; shift ;;
            -h|--help)  _mw_help; return ;;
            *)          break ;;
        esac
    done

    local cmd="${1:-}"
    shift 2>/dev/null

    if [[ -z "$cmd" ]]; then
        _mw_usage
        return
    fi

    # Inject global flags into subcommand args
    local -a _args=()
    [[ $_mw_global_json -eq 1 ]] && _args+=(--json)
    [[ -n "$_mw_global_limit" ]] && _args+=(-n "$_mw_global_limit")
    _args+=("$@")

    case "$cmd" in
        search|s)     _mw_search "${_args[@]}" ;;
        host|h)       _mw_host "${_args[@]}" ;;
        services|svc) _mw_services "${_args[@]}" ;;
        certs|c)      _mw_certs "${_args[@]}" ;;
        domains|d)    _mw_domains "${_args[@]}" ;;
        export|x)     _mw_export "${_args[@]}" ;;
        ips|ip)       _mw_ips "${_args[@]}" ;;
        stats)        _mw_stats "${_args[@]}" ;;
        status)       _mw_status "${_args[@]}" ;;
        dns)          _mw_dns "${_args[@]}" ;;
        facets)       _mw_facets "${_args[@]}" ;;
        geomap|geo)   _mw_geomap "${_args[@]}" ;;
        scan)         _mw_scan "${_args[@]}" ;;
        count)        _mw_count "${_args[@]}" ;;
        help)         _mw_help ;;
        *)
            _mw_err "unknown command '$cmd'"
            echo "  type 'mw help' for usage" >&2
            return 1
            ;;
    esac
}

# ── search ───────────────────────────────────────────────────────────────────

_mw_search() {
    local mode="" count=0 limit=50 page=1 raw=0
    while [[ "${1:-}" == -* ]]; do
        case "$1" in
            -s|--services) mode="services"; shift ;;
            -c|--count)    count=1; shift ;;
            -n|--limit)    limit="$2"; shift 2 ;;
            -p|--page)     page="$2"; shift 2 ;;
            --json)        raw=1; shift ;;
            -h|--help)
                cat <<'EOF'
Usage: mw search [-s] [-c] [-n limit] [-p page] <MeowQL query>

Options:
  -s, --services   service-centric results (shows ports, banners, products)
  -c, --count      print only the result count
  -n, --limit N    max results (default: 50)
  -p, --page  N    page number
  --json           raw JSON output

Examples:
  mw search 'port:443 country:FR'
  mw search -s 'service:ssh'
  mw search -c 'port:22'
EOF
                return ;;
            *) shift ;;
        esac
    done

    local q="$*"
    if [[ -z "$q" ]]; then
        _mw_err "query required"; echo "  mw search <MeowQL query>" >&2; return 1
    fi

    local ep="/search"
    [[ "$mode" == "services" ]] && ep="/search/services"

    local result
    result=$(_mw_get "$ep" -G --data-urlencode "q=$q" -d "limit=$limit" -d "page=$page") || {
        _mw_err "request failed"; return 1
    }

    if [[ $count -eq 1 ]]; then
        echo "$result" | _mw_raw '.total // 0'
        return
    fi

    if [[ $raw -eq 1 ]]; then
        echo "$result" | _mw_json '.'; return
    fi

    if [[ "$mode" == "services" ]]; then
        local total=$(echo "$result" | _mw_raw '.total // 0')
        _mw_hdr "Services: $total results (page $page)"
        echo "$result" | _mw_raw '
            .services // [] | .[] |
            "\(.ip):\(.port)\t\(.service // "-")\t\(.product // "")\(.version // "" | if . != "" then " "+. else "" end)\t\(.country_code // "")\t\(.http_title // .banner // "" | .[0:60])"
        ' | column -t -s $'\t'
    else
        local total=$(echo "$result" | _mw_raw '.total // 0')
        _mw_hdr "Hosts: $total results (page $page)"
        echo "$result" | _mw_raw '
            .hosts // [] | .[] |
            "\(.ip)\t\(.country_code // "")\t\(.as_org // "" | .[0:30])\t\(.cloud_provider // "")\tports:\(.open_ports_count // 0)"
        ' | column -t -s $'\t'
    fi
}

# ── host ─────────────────────────────────────────────────────────────────────

_mw_host() {
    local raw=0 ip=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json)        raw=1; shift ;;
            -n|--limit)    shift 2 ;; # ignored for host
            -h|--help)
                cat <<'EOF'
Usage: mw host <ip>

Shows detailed info for a single host: geo, services, certs, domains.

Options:
  --json    raw JSON output

Examples:
  mw host 192.168.1.1
  mw host 10.0.0.1 --json
EOF
                return ;;
            *)  ip="$1"; shift ;;
        esac
    done

    if [[ -z "$ip" ]]; then
        _mw_err "ip required"; echo "  mw host <ip>" >&2; return 1
    fi

    local result
    result=$(_mw_get "/hosts/$ip") || { _mw_err "host not found: $ip"; return 1; }

    if [[ $raw -eq 1 ]]; then echo "$result" | _mw_json '.'; return; fi

    # Header
    local ip=$(echo "$result" | _mw_raw '.ip')
    local cc=$(echo "$result" | _mw_raw '.country_code // ""')
    local city=$(echo "$result" | _mw_raw '.city // ""')
    local org=$(echo "$result" | _mw_raw '.as_org // ""')
    local asn=$(echo "$result" | _mw_raw '.asn // ""')
    local cloud=$(echo "$result" | _mw_raw '.cloud_provider // ""')
    local ports=$(echo "$result" | _mw_raw '.open_ports_count // 0')

    _mw_hdr "$ip"
    [[ -n "$cc" ]]    && printf "  %-14s %s %s\n" "Location:" "$cc" "$city"
    [[ -n "$org" ]]   && printf "  %-14s AS%s %s\n" "Network:" "$asn" "$org"
    [[ -n "$cloud" ]] && printf "  %-14s %s\n" "Cloud:" "$cloud"
    printf "  %-14s %s\n" "Open ports:" "$ports"
    echo

    # Services table
    local svc_count=$(echo "$result" | _mw_raw '.services // [] | length')
    if [[ "$svc_count" -gt 0 ]]; then
        _mw_hdr "Services"
        printf "  ${_mw_d}%-7s %-14s %-24s %s${_mw_0}\n" "PORT" "SERVICE" "PRODUCT" "BANNER"
        echo "$result" | _mw_raw '
            .services // [] | .[] |
            "  \(.port)\t\(.service // "-")\t\(.product // "")\(.version // "" | if . != "" then " "+. else "" end)\t\(.banner // "" | .[0:50] | gsub("[\n\r\t]+"; " "))"
        ' | column -t -s $'\t'
        echo
    fi

    # Domains
    local dom_count=$(echo "$result" | _mw_raw '.domains // [] | length')
    if [[ "$dom_count" -gt 0 ]]; then
        _mw_hdr "Domains"
        echo "$result" | _mw_raw '.domains // [] | .[] | "  \(.domain)  (\(.source))"'
        echo
    fi

    # Certificates
    local cert_count=$(echo "$result" | _mw_raw '.certificates // [] | length')
    if [[ "$cert_count" -gt 0 ]]; then
        _mw_hdr "Certificates"
        echo "$result" | _mw_raw '.certificates // [] | .[] | "  \(.subject_cn // "?")  issued by \(.issuer_cn // "?")"'
    fi
}

# ── services ─────────────────────────────────────────────────────────────────

_mw_services() {
    local query="" service="" product="" limit=50 page=1 raw=0
    while [[ "${1:-}" == -* ]]; do
        case "$1" in
            -s|--service) service="$2"; shift 2 ;;
            -P|--product) product="$2"; shift 2 ;;
            -n|--limit)   limit="$2"; shift 2 ;;
            -p|--page)    page="$2"; shift 2 ;;
            --json)       raw=1; shift ;;
            -h|--help)
                cat <<'EOF'
Usage: mw services [-s service] [-P product] [-n limit] [-p page] [query]

Search services across all hosts.

Options:
  -s, --service NAME   filter by service name (ssh, http, etc.)
  -P, --product NAME   filter by product name
  -n, --limit N        max results (default: 50)
  -p, --page N         page number
  --json               raw JSON output

Examples:
  mw services -s ssh
  mw services -P nginx
  mw services -s http -P Apache
EOF
                return ;;
            *) shift ;;
        esac
    done
    query="$*"

    local -a params=(-d "limit=$limit" -d "page=$page")
    [[ -n "$query" ]]   && params+=(--data-urlencode "q=$query")
    [[ -n "$service" ]] && params+=(--data-urlencode "service=$service")
    [[ -n "$product" ]] && params+=(--data-urlencode "product=$product")

    local result
    result=$(_mw_get "/services" -G "${params[@]}") || { _mw_err "request failed"; return 1; }

    if [[ $raw -eq 1 ]]; then echo "$result" | _mw_json '.'; return; fi

    _mw_hdr "Services"
    echo "$result" | _mw_raw '
        .services // [] | .[] |
        "\(.ip):\(.port)\t\(.service // "-")\t\(.product // "")\(.version // "" | if . != "" then " "+. else "" end)\t\(.country_code // "")\t\(.banner // "" | .[0:50] | gsub("[\n\r\t]+"; " "))"
    ' | column -t -s $'\t'
}

# ── certs ────────────────────────────────────────────────────────────────────

_mw_certs() {
    local query="" subject="" issuer="" limit=50 raw=0
    while [[ "${1:-}" == -* ]]; do
        case "$1" in
            -s|--subject) subject="$2"; shift 2 ;;
            -i|--issuer)  issuer="$2"; shift 2 ;;
            -n|--limit)   limit="$2"; shift 2 ;;
            --json)       raw=1; shift ;;
            -h|--help)
                cat <<'EOF'
Usage: mw certs [-s subject] [-i issuer] [-n limit] [query]

Search TLS certificates.

Options:
  -s, --subject CN   filter by subject CN (supports wildcards)
  -i, --issuer NAME  filter by issuer
  -n, --limit N      max results (default: 50)
  --json             raw JSON output

Examples:
  mw certs -s '*.example.com'
  mw certs -i "Let's Encrypt"
  mw certs example
EOF
                return ;;
            *) shift ;;
        esac
    done
    query="$*"

    local -a params=(-d "limit=$limit")
    [[ -n "$query" ]]   && params+=(--data-urlencode "q=$query")
    [[ -n "$subject" ]] && params+=(--data-urlencode "subject=$subject")
    [[ -n "$issuer" ]]  && params+=(--data-urlencode "issuer=$issuer")

    local result
    result=$(_mw_get "/certificates" -G "${params[@]}") || { _mw_err "request failed"; return 1; }

    if [[ $raw -eq 1 ]]; then echo "$result" | _mw_json '.'; return; fi

    _mw_hdr "Certificates"
    printf "  ${_mw_d}%-40s %-30s %-5s %s${_mw_0}\n" "SUBJECT" "ISSUER" "HOSTS" "SELF"
    echo "$result" | _mw_raw '
        .certificates // [] | .[] |
        "  \(.subject_cn // "?" | .[0:38])\t\(.issuer_cn // "?" | .[0:28])\t\(.host_count // 0)\t\(if .is_self_signed then "yes" else "" end)"
    ' | column -t -s $'\t'
}

# ── domains ──────────────────────────────────────────────────────────────────

_mw_domains() {
    local query="" protocol="" limit=50 page=1 raw=0
    while [[ "${1:-}" == -* ]]; do
        case "$1" in
            -P|--protocol) protocol="$2"; shift 2 ;;
            -n|--limit)    limit="$2"; shift 2 ;;
            -p|--page)     page="$2"; shift 2 ;;
            --json)        raw=1; shift ;;
            -h|--help)
                cat <<'EOF'
Usage: mw domains [-P protocol] [-n limit] [-p page] [query|domain]

Browse or look up domains. If query looks like a domain (has dots, no spaces),
shows services for that specific domain.

Options:
  -P, --protocol PROTO   filter by protocol (http, https, etc.)
  -n, --limit N          max results (default: 50)
  -p, --page N           page number
  --json                 raw JSON output

Examples:
  mw domains example.com           # services for this domain
  mw domains -P https              # all HTTPS domains
  mw domains corp                  # search "corp" in domains
EOF
                return ;;
            *) shift ;;
        esac
    done
    query="$*"

    # Specific domain lookup
    if [[ -n "$query" && "$query" == *.* && ! "$query" == *" "* ]]; then
        local result
        result=$(_mw_get "/domains/$query/services" -G -d "limit=$limit" -d "page=$page") || {
            _mw_err "domain not found: $query"; return 1
        }
        if [[ $raw -eq 1 ]]; then echo "$result" | _mw_json '.'; return; fi
        _mw_hdr "Services for $query"
        printf "  ${_mw_d}%-22s %-8s %-14s %-5s %s${_mw_0}\n" "ENDPOINT" "PROTO" "SERVER" "CODE" "TITLE"
        echo "$result" | _mw_raw '
            .services // [] | .[] |
            "  \(.ip):\(.port)\t\(.protocol // "-")\t\(.server // "")\t\(.status_code // "")\t\(.title // "" | .[0:40] | gsub("[\n\r\t]+"; " "))"
        ' | column -t -s $'\t'
        return
    fi

    local -a params=(-d "limit=$limit" -d "page=$page")
    [[ -n "$query" ]]    && params+=(--data-urlencode "q=$query")
    [[ -n "$protocol" ]] && params+=(--data-urlencode "protocol=$protocol")

    local result
    result=$(_mw_get "/domains" -G "${params[@]}") || { _mw_err "request failed"; return 1; }

    if [[ $raw -eq 1 ]]; then echo "$result" | _mw_json '.'; return; fi

    _mw_hdr "Domains"
    printf "  ${_mw_d}%-35s %-40s %-12s %s${_mw_0}\n" "DOMAIN" "IPS" "PROTO" "SVCS"
    echo "$result" | _mw_raw '
        .domains // [] | .[] |
        (.ips // [] | join(", ")) as $iplist |
        (if (.ip_count // 0) > 3 then $iplist + " (+\(.ip_count - 3))" else $iplist end) as $ips |
        "  \(.domain)\t\($ips)\t\(.protocols // "")\t\(.services_count)"
    ' | column -t -s $'\t'
}

# ── export ───────────────────────────────────────────────────────────────────

_mw_export() {
    local format="json" dtype="hosts" limit=1000
    local country="" port="" service="" asn="" cloud="" tech=""
    while [[ "${1:-}" == -* ]]; do
        case "$1" in
            -f|--format)  format="$2"; shift 2 ;;
            -t|--type)    dtype="$2"; shift 2 ;;
            -n|--limit)   limit="$2"; shift 2 ;;
            --country)    country="$2"; shift 2 ;;
            --port)       port="$2"; shift 2 ;;
            --service)    service="$2"; shift 2 ;;
            --asn)        asn="$2"; shift 2 ;;
            --cloud)      cloud="$2"; shift 2 ;;
            --tech)       tech="$2"; shift 2 ;;
            -h|--help)
                cat <<'EOF'
Usage: mw export [-f json|csv|txt] [-t hosts|services|certificates] [-n limit]
       [--country XX] [--port N] [--service ssh] [--asn N] [--cloud aws] [query]

Options:
  -f, --format FMT   output format: json (default), csv, txt
  -t, --type TYPE    data type: hosts (default), services, certificates
  -n, --limit N      max results (default: 1000)
  --country CODE     filter by country
  --port N           filter by port
  --service NAME     filter by service
  --asn N            filter by ASN
  --cloud NAME       filter by cloud provider
  --tech NAME        filter by technology

Examples:
  mw export -f csv -t services 'port:443'
  mw export --country FR --service ssh
  mw export -f txt 'port:22'       # same as mw ips
EOF
                return ;;
            *) shift ;;
        esac
    done
    local query="$*"

    local -a params=(-d "format=$format" -d "type=$dtype" -d "limit=$limit")
    [[ -n "$query" ]]   && params+=(--data-urlencode "q=$query")
    [[ -n "$country" ]] && params+=(--data-urlencode "country=$country")
    [[ -n "$port" ]]    && params+=(-d "port=$port")
    [[ -n "$service" ]] && params+=(--data-urlencode "service=$service")
    [[ -n "$asn" ]]     && params+=(-d "asn=$asn")
    [[ -n "$cloud" ]]   && params+=(--data-urlencode "cloud=$cloud")
    [[ -n "$tech" ]]    && params+=(--data-urlencode "technology=$tech")

    local result
    result=$(_mw_get "/export" -G "${params[@]}") || { _mw_err "export failed"; return 1; }

    if [[ "$format" == "json" ]]; then
        echo "$result" | _mw_json '.'
    else
        echo "$result"
    fi
}

# ── ips (shortcut: plain ip:port list) ───────────────────────────────────────

_mw_ips() {
    local limit=10000
    local country="" port="" service="" asn="" cloud=""
    while [[ "${1:-}" == -* ]]; do
        case "$1" in
            -n|--limit)  limit="$2"; shift 2 ;;
            --country)   country="$2"; shift 2 ;;
            --port)      port="$2"; shift 2 ;;
            --service)   service="$2"; shift 2 ;;
            --asn)       asn="$2"; shift 2 ;;
            --cloud)     cloud="$2"; shift 2 ;;
            -h|--help)
                cat <<'EOF'
Usage: mw ips [-n limit] [--country XX] [--port N] [--service ssh] [query]

Outputs plain ip:port list, one per line. Pipe-friendly.

Options:
  -n, --limit N      max results (default: 10000)
  --country CODE     filter by country
  --port N           filter by port
  --service NAME     filter by service
  --asn N            filter by ASN
  --cloud NAME       filter by cloud provider

Examples:
  mw ips 'service:ssh' | xargs -I{} ssh {}
  mw ips --port 80 --country FR
  mw ips 'port:22' | wc -l
EOF
                return ;;
            *) shift ;;
        esac
    done
    local query="$*"

    local -a params=(-d "format=txt" -d "limit=$limit")
    [[ -n "$query" ]]   && params+=(--data-urlencode "q=$query")
    [[ -n "$country" ]] && params+=(--data-urlencode "country=$country")
    [[ -n "$port" ]]    && params+=(-d "port=$port")
    [[ -n "$service" ]] && params+=(--data-urlencode "service=$service")
    [[ -n "$asn" ]]     && params+=(-d "asn=$asn")
    [[ -n "$cloud" ]]   && params+=(--data-urlencode "cloud=$cloud")

    _mw_get "/export" -G "${params[@]}"
}

# ── stats ────────────────────────────────────────────────────────────────────

_mw_stats() {
    local raw=0
    while [[ "${1:-}" == -* ]]; do
        case "$1" in
            --json)     raw=1; shift ;;
            -n|--limit) shift 2 ;; # ignored for stats
            -h|--help)  echo "Usage: mw stats [--json]"; return ;;
            *)          shift ;;
        esac
    done

    local result
    result=$(_mw_get "/stats/dashboard") || { _mw_err "request failed"; return 1; }

    if [[ $raw -eq 1 ]]; then echo "$result" | _mw_json '.'; return; fi

    _mw_hdr "Dashboard"
    local hosts=$(echo "$result" | _mw_raw '.total_hosts // 0')
    local svcs=$(echo "$result" | _mw_raw '.total_services // 0')
    local certs=$(echo "$result" | _mw_raw '.total_certificates // 0')
    printf "  Hosts: %s   Services: %s   Certificates: %s\n\n" "$hosts" "$svcs" "$certs"

    _mw_dim "  Top services:"
    echo "$result" | _mw_raw '
        .top_services // [] | .[] | "    \(.service)  \(.count)"
    '
    echo
    _mw_dim "  Top countries:"
    echo "$result" | _mw_raw '
        .top_countries // [] | .[] | "    \(.code) \(.name)  \(.count)"
    '
    echo
    local clouds=$(echo "$result" | _mw_raw '.cloud_providers // [] | length')
    if [[ "$clouds" -gt 0 ]]; then
        _mw_dim "  Cloud providers:"
        echo "$result" | _mw_raw '
            .cloud_providers // [] | .[] | "    \(.provider)  \(.count)"
        '
    fi
}

# ── status ───────────────────────────────────────────────────────────────────

_mw_status() {
    local raw=0
    while [[ "${1:-}" == -* ]]; do
        case "$1" in
            --json)     raw=1; shift ;;
            -n|--limit) shift 2 ;; # ignored for status
            -h|--help)  echo "Usage: mw status [--json]"; return ;;
            *)          shift ;;
        esac
    done

    local result
    result=$(_mw_get "/debug/stats") || { _mw_err "request failed"; return 1; }

    if [[ $raw -eq 1 ]]; then echo "$result" | _mw_json '.'; return; fi

    _mw_hdr "System Status"

    # NATS
    local connected=$(echo "$result" | _mw_raw '.nats.connected // false')
    local nats_url=$(echo "$result" | _mw_raw '.nats.url // "?"')
    local in_msgs=$(echo "$result" | _mw_raw '.nats.in_msgs // 0')
    local out_msgs=$(echo "$result" | _mw_raw '.nats.out_msgs // 0')
    local n_clients=$(echo "$result" | _mw_raw '.nats.total_connections // 0')
    printf "\n"
    _mw_dim "  NATS:"
    if [[ "$connected" == "true" ]]; then
        printf "    connected to %s  (%s clients)\n" "$nats_url" "$n_clients"
        printf "    msgs in: %s  out: %s\n" "$in_msgs" "$out_msgs"
    else
        printf "    disconnected\n"
    fi

    # DB
    local db_hosts=$(echo "$result" | _mw_raw '.database.hosts // 0')
    local db_svcs=$(echo "$result" | _mw_raw '.database.services // 0')
    local db_certs=$(echo "$result" | _mw_raw '.database.certificates // 0')
    printf "\n"
    _mw_dim "  Database:"
    printf "    hosts: %s  services: %s  certs: %s\n" "$db_hosts" "$db_svcs" "$db_certs"

    # Enrichment
    local enriched=$(echo "$result" | _mw_raw '.database.enrichment.enriched // 0')
    local pending=$(echo "$result" | _mw_raw '.database.enrichment.pending // 0')
    local failed=$(echo "$result" | _mw_raw '.database.enrichment.failed // 0')
    local skipped=$(echo "$result" | _mw_raw '.database.enrichment.skipped // 0')
    printf "\n"
    _mw_dim "  Enrichment:"
    printf "    enriched: %s  pending: %s  failed: %s  skipped: %s\n" "$enriched" "$pending" "$failed" "$skipped"

    # Connected peers
    if [[ "$n_clients" -gt 0 ]]; then
        printf "\n"
        _mw_dim "  NATS clients:"
        echo "$result" | _mw_raw '
            .nats.clients // [] | .[] |
            "    [\(.cid)] \(.name // "anonymous")  \(.ip):\(.port)  up:\(.uptime)  subs:\(.subscriptions)"
        '
    fi
    echo
}

# ── dns ──────────────────────────────────────────────────────────────────────

_mw_dns() {
    local raw=0 target=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json)     raw=1; shift ;;
            -n|--limit) shift 2 ;; # ignored for dns
            -h|--help)
                cat <<'EOF'
Usage: mw dns [--json] <domain|ip>

Forward or reverse DNS resolution.

Examples:
  mw dns example.com
  mw dns 8.8.8.8
EOF
                return ;;
            *)  target="$1"; shift ;;
        esac
    done

    if [[ -z "$target" ]]; then
        _mw_err "domain or ip required"; echo "  mw dns <domain|ip>" >&2; return 1
    fi

    local result
    result=$(_mw_get "/tools/dns" -G --data-urlencode "q=$target") || { _mw_err "lookup failed: $target"; return 1; }

    if [[ $raw -eq 1 ]]; then echo "$result" | _mw_json '.'; return; fi

    _mw_hdr "DNS: $target"
    echo "$result" | _mw_json '.'
}

# ── facets ───────────────────────────────────────────────────────────────────

_mw_facets() {
    local raw=0
    while [[ "${1:-}" == -* ]]; do
        case "$1" in
            --json)     raw=1; shift ;;
            -n|--limit) shift 2 ;; # ignored for facets
            -h|--help)  echo "Usage: mw facets [--json]"; return ;;
            *)          shift ;;
        esac
    done

    local result
    result=$(_mw_get "/facets") || { _mw_err "request failed"; return 1; }

    if [[ $raw -eq 1 ]]; then echo "$result" | _mw_json '.'; return; fi

    _mw_hdr "Available Facets"
    echo
    _mw_dim "  Ports:"
    echo "$result" | _mw_raw '.ports // [] | .[] | "    \(.value)\t\(.count)"' | column -t -s $'\t'
    echo
    _mw_dim "  Services:"
    echo "$result" | _mw_raw '.services // [] | .[] | "    \(.value)\t\(.count)"' | column -t -s $'\t'
    echo
    _mw_dim "  Countries:"
    echo "$result" | _mw_raw '.countries // [] | .[] | "    \(.value)\t\(.count)"' | column -t -s $'\t'
    echo
    _mw_dim "  Cloud providers:"
    echo "$result" | _mw_raw '.cloud_providers // [] | .[] | "    \(.value)\t\(.count)"' | column -t -s $'\t'
    echo
    _mw_dim "  ASNs:"
    echo "$result" | _mw_raw '.asns // [] | .[] | "    AS\(.value)\t\(.label // "")\t\(.count)"' | column -t -s $'\t'
}

# ── geomap ───────────────────────────────────────────────────────────────────

_mw_geomap() {
    local country="" query="" port="" service="" asn="" cloud="" raw=0
    while [[ "${1:-}" == -* ]]; do
        case "$1" in
            -c|--country) country="$2"; shift 2 ;;
            --port)       port="$2"; shift 2 ;;
            --service)    service="$2"; shift 2 ;;
            --asn)        asn="$2"; shift 2 ;;
            --cloud)      cloud="$2"; shift 2 ;;
            --json)       raw=1; shift ;;
            -h|--help)
                cat <<'EOF'
Usage: mw geomap [-c COUNTRY] [--port N] [--service ssh] [--asn N] [query]

Geographic distribution of hosts. Use -c for country details.

Options:
  -c, --country CODE   detailed breakdown for a country
  --port N             filter by port
  --service NAME       filter by service
  --asn N              filter by ASN
  --cloud NAME         filter by cloud provider
  --json               raw JSON output

Examples:
  mw geomap                        # world overview
  mw geomap -c FR                  # France details
  mw geomap --service ssh          # SSH worldwide
EOF
                return ;;
            *) shift ;;
        esac
    done
    query="$*"

    local -a params=()
    [[ -n "$query" ]]   && params+=(-G --data-urlencode "q=$query")
    [[ -n "$port" ]]    && params+=(-G -d "port=$port")
    [[ -n "$service" ]] && params+=(-G --data-urlencode "service=$service")
    [[ -n "$asn" ]]     && params+=(-G -d "asn=$asn")
    [[ -n "$cloud" ]]   && params+=(-G --data-urlencode "cloud=$cloud")

    if [[ -n "$country" ]]; then
        local result
        result=$(_mw_get "/geomap/country/$country" "${params[@]}") || { _mw_err "request failed"; return 1; }

        if [[ $raw -eq 1 ]]; then echo "$result" | _mw_json '.'; return; fi

        local name=$(echo "$result" | _mw_raw '.name // .code')
        local hc=$(echo "$result" | _mw_raw '.host_count // 0')
        _mw_hdr "$name ($country) - $hc hosts"
        echo
        _mw_dim "  Top services:"
        echo "$result" | _mw_raw '.top_services // [] | .[] | "    \(.name)\t\(.count)"' | column -t -s $'\t'
        echo
        _mw_dim "  Top ports:"
        echo "$result" | _mw_raw '.top_ports // [] | .[] | "    \(.port)\t\(.count)"' | column -t -s $'\t'
        echo
        _mw_dim "  Top ASNs:"
        echo "$result" | _mw_raw '.top_asns // [] | .[] | "    AS\(.asn)\t\(.as_org)\t\(.count)"' | column -t -s $'\t'
        echo
        _mw_dim "  Top cities:"
        echo "$result" | _mw_raw '.top_cities // [] | .[] | "    \(.name)\t\(.count)"' | column -t -s $'\t'
        return
    fi

    local result
    result=$(_mw_get "/geomap" "${params[@]}") || { _mw_err "request failed"; return 1; }

    if [[ $raw -eq 1 ]]; then echo "$result" | _mw_json '.'; return; fi

    local th=$(echo "$result" | _mw_raw '.totals.hosts // 0')
    local tc=$(echo "$result" | _mw_raw '.totals.countries // 0')
    local ta=$(echo "$result" | _mw_raw '.totals.asns // 0')
    _mw_hdr "Geographic Distribution"
    printf "  %s hosts across %s countries (%s ASNs)\n\n" "$th" "$tc" "$ta"
    printf "  ${_mw_d}%-6s %-28s %7s %7s${_mw_0}\n" "CODE" "COUNTRY" "HOSTS" "CLOUD"
    echo "$result" | _mw_raw '
        .countries // [] | .[] |
        "  \(.code)\t\(.name)\t\(.host_count)\t\(.cloud_count)"
    ' | column -t -s $'\t'
}

# ── scan ─────────────────────────────────────────────────────────────────────

_mw_scan() {
    local target="" ports="1-1000" rate=1000
    while [[ "${1:-}" == -* ]]; do
        case "$1" in
            -p|--ports) ports="$2"; shift 2 ;;
            -r|--rate)  rate="$2"; shift 2 ;;
            -n|--limit) shift 2 ;; # ignored for scan
            --json)     shift ;;   # scan always outputs json
            -h|--help)
                cat <<'EOF'
Usage: mw scan [-p ports] [-r rate] <target>

Submit an on-demand scan job.

Options:
  -p, --ports RANGE   port range (default: 1-1000)
  -r, --rate N        packets per second (default: 1000)

Examples:
  mw scan 10.0.0.0/24
  mw scan -p 1-65535 -r 5000 192.168.1.0/24
EOF
                return ;;
            *) shift ;;
        esac
    done
    target="$1"

    if [[ -z "$target" ]]; then
        _mw_err "target required"; echo "  mw scan <target>" >&2; return 1
    fi

    local result
    result=$(_mw_post "/scan" -d "{\"target\":\"$target\",\"ports\":\"$ports\",\"rate_limit\":$rate}") || {
        _mw_err "scan submission failed"; return 1
    }
    echo "$result" | _mw_json '.'
}

# ── count (shortcut: just the total) ────────────────────────────────────────

_mw_count() {
    while [[ "${1:-}" == -* ]]; do
        case "$1" in
            -n|--limit) shift 2 ;; # ignored for count
            --json)     shift ;;   # count always outputs a number
            -h|--help)
                cat <<'EOF'
Usage: mw count <MeowQL query>

Returns just the number of matching hosts. Useful in scripts.

Examples:
  mw count 'port:22'
  mw count 'country:FR and service:http'
EOF
                return ;;
            *) shift ;;
        esac
    done
    if [[ -z "$1" ]]; then
        _mw_err "query required"; echo "  mw count <MeowQL query>" >&2; return 1
    fi
    _mw_get "/search" -G --data-urlencode "q=$*" -d "limit=1" | _mw_raw '.total // 0'
}

# ── usage (shown when mw is called with no args) ────────────────────────────

_mw_usage() {
    printf "${_mw_b}mw${_mw_0} — meow CLI\n\n"
    printf "  ${_mw_c}search${_mw_0}  s      MeowQL search        ${_mw_c}host${_mw_0}    h   Host details\n"
    printf "  ${_mw_c}services${_mw_0} svc   Browse services      ${_mw_c}certs${_mw_0}   c   TLS certificates\n"
    printf "  ${_mw_c}domains${_mw_0} d      Domain lookup        ${_mw_c}ips${_mw_0}     ip  ip:port list\n"
    printf "  ${_mw_c}stats${_mw_0}          Dashboard stats      ${_mw_c}status${_mw_0}      System status\n"
    printf "  ${_mw_c}export${_mw_0}  x      Export data          ${_mw_c}facets${_mw_0}      Filter facets\n"
    printf "  ${_mw_c}geomap${_mw_0}  geo    Geo distribution     ${_mw_c}dns${_mw_0}         DNS lookup\n"
    printf "  ${_mw_c}scan${_mw_0}           On-demand scan       ${_mw_c}count${_mw_0}       Count hosts\n"
    printf "\n  ${_mw_d}mw help${_mw_0} for full documentation, ${_mw_d}mw <cmd> -h${_mw_0} for command help\n"
    printf "  ${_mw_d}mw -n 10 search ...${_mw_0} to limit results, ${_mw_d}mw --json search ...${_mw_0} for raw JSON\n"
}

# ── help (full documentation) ───────────────────────────────────────────────

_mw_help() {
    cat <<'HELP'
mw — meow network scanner shell interface

Usage: mw [global opts] <command> [options] [arguments]

Commands:
  search, s       MeowQL search (hosts or services)
  host, h         Detailed host information
  services, svc   Search services by name/product/query
  certs, c        Search TLS certificates
  domains, d      Domain intelligence
  export, x       Export data (json/csv/txt)
  ips, ip         Quick ip:port list (pipe-friendly)
  stats           Dashboard overview statistics
  status          System status (NATS, DB, enrichment)
  dns             DNS resolution (forward & reverse)
  facets          Available filter facets
  geomap, geo     Geographic distribution
  scan            Submit on-demand scan
  count           Count matching hosts

Quick examples:
  mw search 'port:443 country:FR'       search hosts
  mw search -s 'service:ssh'            search services
  mw search -c 'port:22'                count only
  mw host 192.168.1.1                   host details
  mw ips 'service:ssh'                  ip:port list
  mw certs -s '*.example.com'           search certs
  mw domains example.com                domain services
  mw export -f csv -t services          CSV export
  mw geomap -c FR                       country breakdown
  mw stats                              dashboard summary
  mw status                             system health
  mw count 'port:80'                    just the number

Global options (before the command):
  -n, --limit N   override default result limit for any command
  --json          raw JSON output (disables formatted display)
  -h, --help      show this help (or command-specific help after the command)

Environment:
  MEOW_URL  API base URL (current: ${MEOW_URL})
  MEOW_KEY  API key (current: ${MEOW_KEY:+(set)})

MeowQL syntax:
  field:value          contains match
  field="exact"        exact match
  field!=value         negation
  field:{a,b,c}        set match
  ip:192.168.0.0/24    CIDR range
  field>N  field<N     numeric comparison
  expr1 expr2          implicit AND
  expr1 or expr2       OR
  not expr             negation
  (a or b) and c       grouping

Fields:
  ip port service product version banner country city
  asn org cloud http.title http.server http.status
  tls.cert.cn tls.jarm tls.self_signed enrichment.*
HELP
}

# ── bash completion ──────────────────────────────────────────────────────────

_mw_complete() {
    local cur="${COMP_WORDS[COMP_CWORD]}"

    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=($(compgen -W "search host services certs domains export ips stats status dns facets geomap scan count help s h svc c d x ip geo --json" -- "$cur"))
        return
    fi

    case "${COMP_WORDS[1]}" in
        search|s)     COMPREPLY=($(compgen -W "-s -c -n -p --services --count --limit --page --json" -- "$cur")) ;;
        services|svc) COMPREPLY=($(compgen -W "-s -P -n -p --service --product --limit --page --json" -- "$cur")) ;;
        certs|c)      COMPREPLY=($(compgen -W "-s -i -n --subject --issuer --limit --json" -- "$cur")) ;;
        domains|d)    COMPREPLY=($(compgen -W "-P -n -p --protocol --limit --page --json" -- "$cur")) ;;
        export|x)     COMPREPLY=($(compgen -W "-f -t -n --format --type --limit --country --port --service --asn --cloud --tech" -- "$cur")) ;;
        ips|ip)       COMPREPLY=($(compgen -W "-n --limit --country --port --service --asn --cloud" -- "$cur")) ;;
        geomap|geo)   COMPREPLY=($(compgen -W "-c --country --port --service --asn --cloud --json" -- "$cur")) ;;
        scan)         COMPREPLY=($(compgen -W "-p -r --ports --rate" -- "$cur")) ;;
        host|h)       COMPREPLY=($(compgen -W "--json" -- "$cur")) ;;
        stats|status|dns|facets) COMPREPLY=($(compgen -W "--json" -- "$cur")) ;;
    esac
}
complete -o default -F _mw_complete mw

# ── startup ──────────────────────────────────────────────────────────────────

if ! command -v jq &>/dev/null; then
    printf "${_mw_r}${_mw_b}warning:${_mw_0} ${_mw_y}jq${_mw_0} is required but not installed\n"
    printf "  install: ${_mw_d}apt install jq${_mw_0} / ${_mw_d}brew install jq${_mw_0} / ${_mw_d}pacman -S jq${_mw_0}\n"
fi

if [[ -t 1 ]]; then
    printf "${_mw_b}meow${_mw_0} shell loaded — ${_mw_c}${MEOW_URL}${_mw_0}\n"
    printf "  type ${_mw_d}mw${_mw_0} for commands, ${_mw_d}mw help${_mw_0} for full docs\n"
fi
`
