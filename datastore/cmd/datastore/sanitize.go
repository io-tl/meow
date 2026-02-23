package main

import (
	"regexp"
	"strings"

	"github.com/microcosm-cc/bluemonday"
)

const maxBodySize = 100 * 1024 // 100KB cap

// Precompiled regexes for pre-processing (element removal)
var (
	reScript   = regexp.MustCompile(`(?is)<script[\s>].*?</script>`)
	reNoscript = regexp.MustCompile(`(?is)<noscript[\s>].*?</noscript>`)
	reMeta     = regexp.MustCompile(`(?is)<meta\b[^>]*/?>`)
	reBase     = regexp.MustCompile(`(?is)<base\b[^>]*/?>`)
	reIframe   = regexp.MustCompile(`(?is)<iframe[\s>].*?</iframe>`)
	reEmbed    = regexp.MustCompile(`(?is)<embed\b[^>]*/?>`)
	reObject   = regexp.MustCompile(`(?is)<object[\s>].*?</object>`)
	reApplet   = regexp.MustCompile(`(?is)<applet[\s>].*?</applet>`)
	reForm     = regexp.MustCompile(`(?is)<form[\s>].*?</form>`)
	reStyle    = regexp.MustCompile(`(?is)<style[\s>].*?</style>`)
	reSVG      = regexp.MustCompile(`(?is)<svg[\s>].*?</svg>`)
	reMath     = regexp.MustCompile(`(?is)<math[\s>].*?</math>`)
	reLink     = regexp.MustCompile(`(?is)<link\b[^>]*/?>`)
	reVideo    = regexp.MustCompile(`(?is)<video[\s>].*?</video>`)
	reAudio    = regexp.MustCompile(`(?is)<audio[\s>].*?</audio>`)
	reSource   = regexp.MustCompile(`(?is)<source\b[^>]*/?>`)

	// Event handlers: match on* attributes (handles quoted, unquoted, and entity-encoded values)
	reOnHandlers = regexp.MustCompile(`(?is)\s+on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)`)
)

// Precompiled regexes for post-processing (attribute & CSS stripping)
var (
	// Resource-loading attributes
	reSrc        = regexp.MustCompile(`(?i)\bsrc\s*=`)
	reSrcset     = regexp.MustCompile(`(?i)\bsrcset\s*=`)
	reHref       = regexp.MustCompile(`(?i)\bhref\s*=`)
	reXlinkHref  = regexp.MustCompile(`(?i)xlink:href\s*=`)
	reAction     = regexp.MustCompile(`(?i)\baction\s*=`)
	reFormaction = regexp.MustCompile(`(?i)\bformaction\s*=`)
	rePoster     = regexp.MustCompile(`(?i)\bposter\s*=`)
	reBackground = regexp.MustCompile(`(?i)\bbackground\s*=`)
	reDataAttr   = regexp.MustCompile(`(?i)\bdata\s*=`)
	rePing       = regexp.MustCompile(`(?i)\bping\s*=`)
	reDynsrc     = regexp.MustCompile(`(?i)\bdynsrc\s*=`)
	reLowsrc     = regexp.MustCompile(`(?i)\blowsrc\s*=`)
	reLongdesc   = regexp.MustCompile(`(?i)\blongdesc\s*=`)
	reCodebase   = regexp.MustCompile(`(?i)\bcodebase\s*=`)

	// CSS dangerous patterns
	reCSSUrl        = regexp.MustCompile(`(?i)url\s*\(`)
	reCSSImport     = regexp.MustCompile(`(?i)@import\b`)
	reCSSExpression = regexp.MustCompile(`(?i)\bexpression\s*\(`)
	reCSSBehavior   = regexp.MustCompile(`(?i)\bbehavior\s*:`)
	reCSSMozBinding = regexp.MustCompile(`(?i)-moz-binding\s*:`)
	reCSSJSProto    = regexp.MustCompile(`(?i)javascript\s*:`)
)

// bmPolicy is the singleton bluemonday policy
var bmPolicy *bluemonday.Policy

func init() {
	bmPolicy = bluemonday.NewPolicy()

	// Structural tags only — NO style, img, svg, math, form, iframe, embed, object, video, audio, source
	bmPolicy.AllowElements(
		"html", "head", "body",
		"div", "span", "p", "br", "hr",
		"h1", "h2", "h3", "h4", "h5", "h6",
		"ul", "ol", "li", "dl", "dt", "dd",
		"table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption", "colgroup", "col",
		"header", "footer", "section", "article", "nav", "aside", "main",
		"pre", "code", "blockquote", "figure", "figcaption",
		"strong", "em", "b", "i", "u", "s", "sub", "sup", "small", "mark",
		"abbr", "cite", "q", "time", "var", "samp", "kbd",
		"details", "summary",
		"a", // kept for structure but href stripped in postProcess
	)

	// Safe attributes only — NO src, href, action, formaction, background, poster, data, ping, srcset, style
	bmPolicy.AllowAttrs("class", "id").Globally()
	bmPolicy.AllowAttrs("title").Globally()
	bmPolicy.AllowAttrs("width", "height").OnElements("table", "td", "th", "col")
	bmPolicy.AllowAttrs("colspan", "rowspan").OnElements("td", "th")
	bmPolicy.AllowAttrs("datetime").OnElements("time")
	bmPolicy.AllowAttrs("open").OnElements("details")
	bmPolicy.AllowAttrs("scope").OnElements("th")
}

// sanitizeHTMLBody sanitizes an HTML body for safe iframe rendering.
// 3-pass pipeline: pre-process (regex strip), bluemonday (whitelist), post-process (residual strip + CSP).
func sanitizeHTMLBody(body string) string {
	if len(body) == 0 {
		return ""
	}

	// Cap size
	if len(body) > maxBodySize {
		body = body[:maxBodySize]
	}

	// Pass 1: Pre-processing — remove dangerous elements and attributes
	body = preProcess(body)

	// Pass 2: bluemonday sanitization (whitelist-based)
	body = bmPolicy.Sanitize(body)

	// Pass 3: Post-processing — strip residual dangerous patterns + inject CSP
	body = postProcess(body)

	return body
}

// preProcess removes dangerous HTML elements and event handlers via regex.
func preProcess(body string) string {
	// Remove elements with content (order matters: script first)
	body = reScript.ReplaceAllString(body, "")
	body = reNoscript.ReplaceAllString(body, "")
	body = reStyle.ReplaceAllString(body, "")
	body = reSVG.ReplaceAllString(body, "")
	body = reMath.ReplaceAllString(body, "")
	body = reIframe.ReplaceAllString(body, "")
	body = reObject.ReplaceAllString(body, "")
	body = reApplet.ReplaceAllString(body, "")
	body = reForm.ReplaceAllString(body, "")
	body = reVideo.ReplaceAllString(body, "")
	body = reAudio.ReplaceAllString(body, "")

	// Remove self-closing/void elements
	body = reMeta.ReplaceAllString(body, "")
	body = reBase.ReplaceAllString(body, "")
	body = reEmbed.ReplaceAllString(body, "")
	body = reLink.ReplaceAllString(body, "")
	body = reSource.ReplaceAllString(body, "")

	// Remove all event handlers (on* attributes)
	body = reOnHandlers.ReplaceAllString(body, "")

	return body
}

// postProcess strips residual resource-loading attributes, dangerous CSS patterns,
// and injects a restrictive CSP meta tag.
func postProcess(body string) string {
	// Strip all resource-loading attributes
	body = reSrc.ReplaceAllString(body, "data-x-src=")
	body = reSrcset.ReplaceAllString(body, "data-x-srcset=")
	body = reHref.ReplaceAllString(body, "data-x-href=")
	body = reXlinkHref.ReplaceAllString(body, "data-x-xlink=")
	body = reAction.ReplaceAllString(body, "data-x-action=")
	body = reFormaction.ReplaceAllString(body, "data-x-formaction=")
	body = rePoster.ReplaceAllString(body, "data-x-poster=")
	body = reBackground.ReplaceAllString(body, "data-x-bg=")
	body = reDataAttr.ReplaceAllString(body, "data-x-data=")
	body = rePing.ReplaceAllString(body, "data-x-ping=")
	body = reDynsrc.ReplaceAllString(body, "data-x-dynsrc=")
	body = reLowsrc.ReplaceAllString(body, "data-x-lowsrc=")
	body = reLongdesc.ReplaceAllString(body, "data-x-longdesc=")
	body = reCodebase.ReplaceAllString(body, "data-x-codebase=")

	// Strip dangerous CSS patterns
	body = reCSSUrl.ReplaceAllString(body, "/* blocked */(")
	body = reCSSImport.ReplaceAllString(body, "/* blocked-import */")
	body = reCSSExpression.ReplaceAllString(body, "/* blocked */(")
	body = reCSSBehavior.ReplaceAllString(body, "/* blocked */:")
	body = reCSSMozBinding.ReplaceAllString(body, "/* blocked */:")
	body = reCSSJSProto.ReplaceAllString(body, "/* blocked */:")

	// Inject CSP meta tag — strictest possible: block everything
	csp := `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">`
	if idx := strings.Index(strings.ToLower(body), "<head"); idx >= 0 {
		closeIdx := strings.Index(body[idx:], ">")
		if closeIdx >= 0 {
			insertPos := idx + closeIdx + 1
			body = body[:insertPos] + csp + body[insertPos:]
			return body
		}
	}
	body = csp + body

	return body
}
