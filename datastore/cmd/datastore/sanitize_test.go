package main

import (
	"strings"
	"testing"
)

func TestSanitizeScriptTags(t *testing.T) {
	input := `<div>Hello</div><script>alert('xss')</script><p>World</p>`
	result := sanitizeHTMLBody(input)
	if strings.Contains(result, "<script") || strings.Contains(result, "alert") {
		t.Errorf("script tag not removed: %s", result)
	}
	if !strings.Contains(result, "Hello") || !strings.Contains(result, "World") {
		t.Errorf("content lost: %s", result)
	}
}

func TestSanitizeEventHandlers(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"onclick", `<div onclick="alert(1)">test</div>`},
		{"onerror", `<img onerror="alert(1)" alt="test">`},
		{"onload", `<body onload="alert(1)">test</body>`},
		{"onmouseover", `<span onmouseover="evil()">hover</span>`},
		{"onfocus", `<input onfocus="alert(1)">`},
		{"onblur", `<input onblur="alert(1)">`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeHTMLBody(tt.input)
			if strings.Contains(strings.ToLower(result), tt.name+"=") {
				t.Errorf("event handler %s not removed: %s", tt.name, result)
			}
		})
	}
}

func TestSanitizeHrefSrcNeutralized(t *testing.T) {
	input := `<div><a href="https://evil.com">link</a><img src="https://evil.com/img.png" alt="test"></div>`
	result := sanitizeHTMLBody(input)
	lower := strings.ToLower(result)
	if strings.Contains(lower, " href=") || strings.Contains(lower, `"href=`) {
		t.Errorf("href not neutralized: %s", result)
	}
	if strings.Contains(lower, " src=") || strings.Contains(lower, `"src=`) {
		t.Errorf("src not neutralized: %s", result)
	}
}

func TestSanitizeMetaRefresh(t *testing.T) {
	input := `<head><meta http-equiv="refresh" content="0;url=https://evil.com"></head><body>content</body>`
	result := sanitizeHTMLBody(input)
	if strings.Contains(strings.ToLower(result), "<meta") && !strings.Contains(result, "Content-Security-Policy") {
		t.Errorf("non-CSP meta tag not removed: %s", result)
	}
}

func TestSanitizeBaseTag(t *testing.T) {
	input := `<head><base href="https://evil.com/"></head><body>content</body>`
	result := sanitizeHTMLBody(input)
	if strings.Contains(strings.ToLower(result), "<base") {
		t.Errorf("base tag not removed: %s", result)
	}
}

func TestSanitizeIframeFormEmbed(t *testing.T) {
	tests := []struct {
		name  string
		input string
		tag   string
	}{
		{"iframe", `<div><iframe src="evil.com"></iframe></div>`, "iframe"},
		{"form", `<div><form action="evil.com"><input></form></div>`, "form"},
		{"embed", `<div><embed src="evil.com"></div>`, "embed"},
		{"object", `<div><object data="evil.com">fallback</object></div>`, "object"},
		{"applet", `<div><applet code="evil.class">fallback</applet></div>`, "applet"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeHTMLBody(tt.input)
			if strings.Contains(strings.ToLower(result), "<"+tt.tag) {
				t.Errorf("%s tag not removed: %s", tt.tag, result)
			}
		})
	}
}

func TestSanitizeStyleElementRemoved(t *testing.T) {
	input := `<head><style>body { color: red; }</style></head><body><p>text</p></body>`
	result := sanitizeHTMLBody(input)
	if strings.Contains(strings.ToLower(result), "<style") {
		t.Errorf("style element not removed: %s", result)
	}
	if !strings.Contains(result, "text") {
		t.Errorf("content lost: %s", result)
	}
}

func TestSanitizeSVGRemoved(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"svg_onload", `<div><svg onload="alert(1)"><circle r="10"/></svg></div>`},
		{"svg_script", `<div><svg><script>alert(1)</script></svg></div>`},
		{"svg_foreignObject", `<div><svg><foreignObject><body onload="alert(1)"></foreignObject></svg></div>`},
		{"svg_xlink", `<div><svg xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="https://evil.com/x.svg#xss"/></svg></div>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeHTMLBody(tt.input)
			if strings.Contains(strings.ToLower(result), "<svg") {
				t.Errorf("svg not removed: %s", result)
			}
			if strings.Contains(strings.ToLower(result), "alert") {
				t.Errorf("script payload survived: %s", result)
			}
		})
	}
}

func TestSanitizeMathMLRemoved(t *testing.T) {
	input := `<div><math><mi>x</mi></math></div>`
	result := sanitizeHTMLBody(input)
	if strings.Contains(strings.ToLower(result), "<math") {
		t.Errorf("math element not removed: %s", result)
	}
}

func TestSanitizeNoscriptRemoved(t *testing.T) {
	input := `<div><noscript><img src="https://evil.com/track.png"></noscript></div>`
	result := sanitizeHTMLBody(input)
	if strings.Contains(strings.ToLower(result), "<noscript") {
		t.Errorf("noscript not removed: %s", result)
	}
}

func TestSanitizeXlinkHref(t *testing.T) {
	input := `<div xlink:href="https://evil.com">test</div>`
	result := sanitizeHTMLBody(input)
	if strings.Contains(strings.ToLower(result), "xlink:href=") {
		t.Errorf("xlink:href not neutralized: %s", result)
	}
}

func TestSanitizeSrcset(t *testing.T) {
	input := `<div srcset="data:image/svg+xml,<svg onload='alert(1)'> 1x">test</div>`
	result := sanitizeHTMLBody(input)
	lower := strings.ToLower(result)
	if strings.Contains(lower, "srcset=") && !strings.Contains(lower, "data-x-srcset=") {
		t.Errorf("srcset not neutralized: %s", result)
	}
}

func TestSanitizeFormaction(t *testing.T) {
	input := `<div><button formaction="https://evil.com/submit">Click</button></div>`
	result := sanitizeHTMLBody(input)
	lower := strings.ToLower(result)
	if strings.Contains(lower, "formaction=") && !strings.Contains(lower, "data-x-formaction=") {
		t.Errorf("formaction not neutralized: %s", result)
	}
}

func TestSanitizePingAttribute(t *testing.T) {
	input := `<a ping="https://evil.com/track">link</a>`
	result := sanitizeHTMLBody(input)
	lower := strings.ToLower(result)
	if strings.Contains(lower, " ping=") || strings.Contains(lower, `"ping=`) {
		t.Errorf("ping attribute not neutralized: %s", result)
	}
}

func TestSanitizeBackgroundAttribute(t *testing.T) {
	input := `<body background="https://evil.com/bg.png"><p>text</p></body>`
	result := sanitizeHTMLBody(input)
	lower := strings.ToLower(result)
	if strings.Contains(lower, "background=") && !strings.Contains(lower, "data-x-bg=") {
		t.Errorf("background attribute not neutralized: %s", result)
	}
}

func TestSanitizePosterAttribute(t *testing.T) {
	input := `<div poster="https://evil.com/img.png">text</div>`
	result := sanitizeHTMLBody(input)
	lower := strings.ToLower(result)
	if strings.Contains(lower, "poster=") && !strings.Contains(lower, "data-x-poster=") {
		t.Errorf("poster attribute not neutralized: %s", result)
	}
}

func TestSanitizeCSSExpression(t *testing.T) {
	// Even though <style> is stripped, test that inline style expression() would be caught
	input := `<div style="width: expression(alert(1))">test</div>`
	result := sanitizeHTMLBody(input)
	lower := strings.ToLower(result)
	if strings.Contains(lower, "expression(") {
		t.Errorf("CSS expression() not blocked: %s", result)
	}
}

func TestSanitizeCSSBehavior(t *testing.T) {
	input := `<div style="behavior: url(xss.htc)">test</div>`
	result := sanitizeHTMLBody(input)
	lower := strings.ToLower(result)
	if strings.Contains(lower, "behavior:") && !strings.Contains(lower, "/* blocked */") {
		t.Errorf("CSS behavior not blocked: %s", result)
	}
}

func TestSanitizeCSSMozBinding(t *testing.T) {
	input := `<div style="-moz-binding: url(xss.xml#xss)">test</div>`
	result := sanitizeHTMLBody(input)
	lower := strings.ToLower(result)
	if strings.Contains(lower, "-moz-binding:") && !strings.Contains(lower, "/* blocked */") {
		t.Errorf("CSS -moz-binding not blocked: %s", result)
	}
}

func TestSanitizeJavascriptProtocol(t *testing.T) {
	input := `<div style="background: javascript:alert(1)">test</div>`
	result := sanitizeHTMLBody(input)
	lower := strings.ToLower(result)
	if strings.Contains(lower, "javascript:") && !strings.Contains(lower, "/* blocked */") {
		t.Errorf("javascript: protocol not blocked: %s", result)
	}
}

func TestSanitizeCSSUrlAndImport(t *testing.T) {
	// Style elements are now fully stripped, but test url() in any residual context
	input := `<div style="background: url(https://evil.com/bg.png)">content</div>`
	result := sanitizeHTMLBody(input)
	lower := strings.ToLower(result)
	if strings.Contains(lower, "url(h") || strings.Contains(lower, "url(\"h") {
		t.Errorf("CSS url() not neutralized: %s", result)
	}
}

func TestSanitizeVideoAudio(t *testing.T) {
	input := `<div><video src="evil.mp4" autoplay><source src="evil.webm"></video><audio src="evil.mp3"></audio></div>`
	result := sanitizeHTMLBody(input)
	lower := strings.ToLower(result)
	if strings.Contains(lower, "<video") || strings.Contains(lower, "<audio") || strings.Contains(lower, "<source") {
		t.Errorf("video/audio/source not removed: %s", result)
	}
}

func TestSanitizeLinkRemoved(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"stylesheet", `<head><link rel="stylesheet" href="https://evil.com/style.css"></head>`},
		{"preload", `<head><link rel="preload" href="https://evil.com/font.woff2" as="font"></head>`},
		{"prefetch", `<head><link rel="prefetch" href="https://evil.com/page.html"></head>`},
		{"icon", `<head><link rel="icon" href="https://evil.com/favicon.ico"></head>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeHTMLBody(tt.input)
			if strings.Contains(strings.ToLower(result), "<link") {
				t.Errorf("link tag not removed: %s", result)
			}
		})
	}
}

func TestSanitizeBodyTruncation(t *testing.T) {
	large := strings.Repeat("A", 200*1024)
	result := sanitizeHTMLBody(large)
	if len(result) > maxBodySize+1024 { // allow some overhead from CSP meta injection
		t.Errorf("body not truncated: got %d bytes", len(result))
	}
}

func TestSanitizeEmptyBody(t *testing.T) {
	result := sanitizeHTMLBody("")
	if result != "" {
		t.Errorf("empty body should return empty: got %q", result)
	}
}

func TestSanitizeCSPInjected(t *testing.T) {
	input := `<html><head><title>Test</title></head><body><p>Hello</p></body></html>`
	result := sanitizeHTMLBody(input)
	if !strings.Contains(result, `Content-Security-Policy`) {
		t.Errorf("CSP meta not injected: %s", result)
	}
	if !strings.Contains(result, `default-src 'none'`) {
		t.Errorf("CSP policy missing default-src: %s", result)
	}
}

func TestSanitizeHTMLEntitiesContournement(t *testing.T) {
	input := `<div>&#60;script&#62;alert(1)&#60;/script&#62;</div>`
	result := sanitizeHTMLBody(input)
	if strings.Contains(result, "<script") {
		t.Errorf("HTML entity encoded script not handled: %s", result)
	}
}

func TestSanitizeStructuralTagsPreserved(t *testing.T) {
	input := `<div class="container"><h1>Title</h1><p>Paragraph</p><table><tr><td>Cell</td></tr></table></div>`
	result := sanitizeHTMLBody(input)
	for _, tag := range []string{"<div", "<h1>", "<p>", "<table>", "<tr>", "<td>"} {
		if !strings.Contains(result, tag) {
			t.Errorf("structural tag %s was removed: %s", tag, result)
		}
	}
}

func TestSanitizeActionAttribute(t *testing.T) {
	input := `<div action="https://evil.com/submit">test</div>`
	result := sanitizeHTMLBody(input)
	lower := strings.ToLower(result)
	if strings.Contains(lower, " action=") || strings.Contains(lower, `"action=`) {
		t.Errorf("action attribute not neutralized: %s", result)
	}
}

func TestSanitizeDataURIInAttributes(t *testing.T) {
	input := `<div data="data:text/html,<script>alert(1)</script>">test</div>`
	result := sanitizeHTMLBody(input)
	lower := strings.ToLower(result)
	// The data= attribute should be rewritten
	if strings.Contains(lower, " data=") && !strings.Contains(lower, "data-x-data=") {
		t.Errorf("data attribute not neutralized: %s", result)
	}
}
