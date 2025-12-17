package app

import (
	"bytes"
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
	"gopkg.in/yaml.v3"
)

//go:embed docs/*.md docs/**/*.md
var docsFS embed.FS

//go:embed templates/*.html
var webTemplatesFS embed.FS

//go:embed static
var staticFS embed.FS

// DocPage represents a parsed documentation page
type DocPage struct {
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Slug        string `yaml:"-"`
	Content     template.HTML
}

// DocsData holds template data for docs pages
type DocsData struct {
	Title       string
	Description string
	Content     template.HTML
	CurrentPath string
	Version     string
	NavTools    []NavTool
}

// NavTool represents a tool in the navigation
type NavTool struct {
	Name string
	Slug string
}

// LandingData holds template data for the landing page
type LandingData struct {
	Version   string
	ToolCount int
	Tools     []NavTool
}

// DocsManager handles documentation serving
type DocsManager struct {
	pages         map[string]*DocPage
	landingTmpl   *template.Template
	docsTmpl      *template.Template
	md            goldmark.Markdown
	version       string
	tools         []NavTool
}

// NewDocsManager creates a new documentation manager
func NewDocsManager(version string, toolNames []string) (*DocsManager, error) {
	dm := &DocsManager{
		pages:   make(map[string]*DocPage),
		version: version,
		md: goldmark.New(
			goldmark.WithExtensions(extension.GFM, extension.Table),
			goldmark.WithParserOptions(parser.WithAutoHeadingID()),
			goldmark.WithRendererOptions(html.WithUnsafe()),
		),
	}

	// Build tools nav
	for _, name := range toolNames {
		dm.tools = append(dm.tools, NavTool{
			Name: name,
			Slug: strings.ToLower(strings.ReplaceAll(name, "_", "-")),
		})
	}

	// Parse templates
	var err error
	dm.landingTmpl, err = template.ParseFS(webTemplatesFS, "templates/landing.html")
	if err != nil {
		return nil, err
	}

	dm.docsTmpl, err = template.ParseFS(webTemplatesFS, "templates/docs_base.html", "templates/docs_content.html")
	if err != nil {
		return nil, err
	}

	// Load all docs
	if err := dm.loadDocs(); err != nil {
		return nil, err
	}

	return dm, nil
}

// loadDocs walks the docs directory and parses all markdown files
func (dm *DocsManager) loadDocs() error {
	return fs.WalkDir(docsFS, "docs", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".md" {
			return nil
		}

		content, err := docsFS.ReadFile(path)
		if err != nil {
			return err
		}

		page, err := dm.parsePage(content)
		if err != nil {
			return err
		}

		// Convert file path to URL slug
		// docs/index.md -> /docs/
		// docs/getting-started.md -> /docs/getting-started
		// docs/tools/login.md -> /docs/tools/login
		slug := strings.TrimPrefix(path, "docs/")
		slug = strings.TrimSuffix(slug, ".md")
		if slug == "index" {
			slug = ""
		}
		page.Slug = "/docs/" + slug
		if page.Slug == "/docs/" {
			page.Slug = "/docs/"
		} else {
			page.Slug = strings.TrimSuffix(page.Slug, "/")
		}

		dm.pages[page.Slug] = page
		return nil
	})
}

// parsePage extracts frontmatter and renders markdown
func (dm *DocsManager) parsePage(content []byte) (*DocPage, error) {
	page := &DocPage{}

	// Check for frontmatter
	if bytes.HasPrefix(content, []byte("---\n")) {
		parts := bytes.SplitN(content[4:], []byte("\n---\n"), 2)
		if len(parts) == 2 {
			if err := yaml.Unmarshal(parts[0], page); err != nil {
				return nil, err
			}
			content = parts[1]
		}
	}

	// Render markdown
	var buf bytes.Buffer
	if err := dm.md.Convert(content, &buf); err != nil {
		return nil, err
	}
	page.Content = template.HTML(buf.String())

	return page, nil
}

// ServeLanding handles the landing page at /
func (dm *DocsManager) ServeLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data := LandingData{
		Version:   dm.version,
		ToolCount: len(dm.tools),
		Tools:     dm.tools,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dm.landingTmpl.ExecuteTemplate(w, "landing", data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// ServeDocs handles documentation pages at /docs/*
func (dm *DocsManager) ServeDocs(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/docs" {
		http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
		return
	}

	// Normalize path
	path = strings.TrimSuffix(path, "/")
	if path == "/docs" {
		path = "/docs/"
	}

	page, ok := dm.pages[path]
	if !ok {
		// Try with trailing slash for index pages
		if page, ok = dm.pages[path+"/"]; !ok {
			http.NotFound(w, r)
			return
		}
	}

	data := DocsData{
		Title:       page.Title,
		Description: page.Description,
		Content:     page.Content,
		CurrentPath: path,
		Version:     dm.version,
		NavTools:    dm.tools,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dm.docsTmpl.ExecuteTemplate(w, "docs_base", data); err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// ServeStatic returns a handler for static files
func (dm *DocsManager) ServeStatic() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
