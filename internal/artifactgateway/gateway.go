// Package artifactgateway exposes the public toolchain mirror alongside the API.
package artifactgateway

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Wrap adds optional artifact routes. mirrorDir is the extracted mirror root
// containing shorebird/, never the server's private data or object-store root.
func Wrap(next http.Handler, mirrorDir, proxyURL string) (http.Handler, error) {
	var files http.Handler
	if mirrorDir != "" {
		root, err := filepath.Abs(mirrorDir)
		if err != nil {
			return nil, err
		}
		root, err = filepath.EvalSymlinks(root)
		if err != nil {
			return nil, fmt.Errorf("artifact mirror: %w", err)
		}
		info, err := os.Stat(filepath.Join(root, "shorebird"))
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("artifact mirror must contain a shorebird directory")
		}
		files = mirrorFiles(root)
	}
	var proxy http.Handler
	if proxyURL != "" {
		target, err := url.Parse(proxyURL)
		if err != nil || target == nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
			return nil, fmt.Errorf("artifact proxy upstream must be an HTTP(S) URL without credentials, query, or fragment")
		}
		proxy = http.StripPrefix("/download.flutter.io", httputil.NewSingleHostReverseProxy(target))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/artifacts/") && files != nil {
			files.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/download.flutter.io/") && proxy != nil {
			if !readMethod(w, r) {
				return
			}
			proxy.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	}), nil
}

func readMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func mirrorFiles(root string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !readMethod(w, r) {
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/artifacts/"), "/")
		if len(parts) < 2 || parts[0] != "shorebird" {
			http.NotFound(w, r)
			return
		}
		path := root
		for _, part := range parts {
			if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\\\x00:") {
				http.NotFound(w, r)
				return
			}
			path = filepath.Join(path, part)
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				http.NotFound(w, r)
				return
			}
		}
		file, err := os.Open(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		// ServeContent provides range requests, HEAD, and conditional downloads.
		http.ServeContent(w, r, info.Name(), info.ModTime(), file)
	})
}
