package app

import (
	"bytes"
	"html/template"
	"log"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/zerodha/kite-mcp-server/kc/legaldocs"
)

// termsMarkdown is the raw Terms of Service markdown, imported from the
// legaldocs package (which embeds kc/legaldocs/TERMS.md at build time).
// Exposed as a package-level alias so the HTTP handler can serve it
// verbatim under ?format=md without an extra indirection.
var termsMarkdown = legaldocs.Terms

// privacyMarkdown is the same for the Privacy Policy, sourced from
// kc/legaldocs/PRIVACY.md.
var privacyMarkdown = legaldocs.Privacy

// termsHTML is the rendered Terms of Service content, populated at package
// initialisation by running termsMarkdown through goldmark. Consumed by
// the /terms HTTP handler in serveLegalPages.
//
// Declared as a package-level variable (not a const) so it can be rendered
// at init time. Older tests in ratelimit_test.go assert on this value
// directly; they continue to pass because the rendered HTML preserves all
// keywords they match against ("Terms of Service", "SEBI",
// "Chennai, Tamil Nadu, India", etc.) from the source markdown.
var termsHTML template.HTML

// privacyHTML is the rendered Privacy Policy content, populated the same
// way from privacyMarkdown at package initialisation.
var privacyHTML template.HTML

// markdownRenderer is the shared goldmark instance used to render the
// embedded markdown documents.
//
// Extensions:
//   - extension.GFM — GitHub-Flavored Markdown (tables, autolinks,
//     strikethrough, task lists). Tables are load-bearing: both policy
//     documents use them for data categorisation and retention matrices.
//
// Parser options:
//   - parser.WithAutoHeadingID() — auto-generates id="..." on each
//     heading so in-page anchors (e.g. for cross-links from the landing
//     page or Google result deep-links) work without manual mark-up.
//
// Renderer options:
//   - html.WithUnsafe() — allows the inline HTML that appears in our
//     source markdown (e.g. <p style="..."> footers, <br> line breaks)
//     to pass through verbatim. Safe here because the source markdown is
//     author-controlled and embedded at build time; it is NOT user
//     input.
var markdownRenderer = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithParserOptions(parser.WithAutoHeadingID()),
	goldmark.WithRendererOptions(html.WithUnsafe()),
)

// renderMarkdown converts a markdown byte slice into HTML using the
// shared markdownRenderer. The result is typed as template.HTML so it
// can be injected into the legal.html template via {{.Content}} without
// double-escaping.
//
// #nosec G203 -- md is exclusively build-time //go:embed'd legal-doc
// markdown (kc/legaldocs/TERMS.md, PRIVACY.md), never user input. The
// html.WithUnsafe() renderer option is documented above; the template.HTML
// cast is intentional so Go's html/template does not double-escape the
// already-HTML markdown output.
func renderMarkdown(md []byte) (template.HTML, error) {
	var buf bytes.Buffer
	if err := markdownRenderer.Convert(md, &buf); err != nil {
		return "", err
	}
	return template.HTML(buf.String()), nil
}

// init renders the embedded markdown documents into HTML at package load
// time. A failure here is unrecoverable (the markdown is compiled into
// the binary via //go:embed) so we log.Fatalf — the server cannot
// meaningfully serve /privacy or /terms without rendered content, and
// silently serving broken content is worse than refusing to start.
func init() {
	if len(termsMarkdown) == 0 {
		log.Fatalf("legal.go: embedded kc/legaldocs/TERMS.md is empty")
	}
	if len(privacyMarkdown) == 0 {
		log.Fatalf("legal.go: embedded kc/legaldocs/PRIVACY.md is empty")
	}
	var err error
	if termsHTML, err = renderMarkdown(termsMarkdown); err != nil {
		log.Fatalf("legal.go: failed to render kc/legaldocs/TERMS.md: %v", err)
	}
	if privacyHTML, err = renderMarkdown(privacyMarkdown); err != nil {
		log.Fatalf("legal.go: failed to render kc/legaldocs/PRIVACY.md: %v", err)
	}
}
