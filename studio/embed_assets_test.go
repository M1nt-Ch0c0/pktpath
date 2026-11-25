package studio

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestM1WorkbenchLayoutAssetsEmbedded(t *testing.T) {
	web, err := WebFS()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"index.html", "app.js", "plugin-center.js", "styles.css", "workbench-layout.css", "workbench-layout.js"} {
		b, err := fs.ReadFile(web, name)
		if err != nil || len(b) == 0 {
			t.Fatalf("asset %s missing: %v", name, err)
		}
	}
	b, _ := fs.ReadFile(web, "index.html")
	for _, needle := range []string{"workbench-layout.css", "workbench-layout.js", "railSplitter", "chartSplitter", "panelSamples", "sampleBody"} {
		if !strings.Contains(string(b), needle) {
			t.Fatalf("embed HTML missing %s", needle)
		}
	}
}
func TestM1WorkbenchLayoutStaticHandler(t *testing.T) {
	web, err := WebFS()
	if err != nil {
		t.Fatal(err)
	}
	h := http.FileServer(http.FS(web))
	for _, name := range []string{"workbench-layout.js", "workbench-layout.css"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/"+name, nil))
		if w.Code != 200 || w.Body.Len() == 0 {
			t.Fatalf("static %s: status %d", name, w.Code)
		}
	}
}
