package handlers

import (
	"net/http"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// Signed storage and diagnostic URLs carry bearer grants in their query. Log
// only the path, including for unknown query fields, while leaving the actual
// request untouched for signature validation and endpoint behavior.
type pathOnlyLogFormatter struct {
	chimw.DefaultLogFormatter
}

func (f *pathOnlyLogFormatter) NewLogEntry(r *http.Request) chimw.LogEntry {
	safeRequest := *r
	safeURL := *r.URL
	safeURL.RawQuery = ""
	safeURL.ForceQuery = false
	safeURL.Fragment = ""
	safeURL.User = nil
	safeRequest.URL = &safeURL
	safeRequest.RequestURI = safeURL.EscapedPath()
	if safeRequest.RequestURI == "" {
		safeRequest.RequestURI = "/"
	}
	return f.DefaultLogFormatter.NewLogEntry(&safeRequest)
}

func pathOnlyRequestLogger(logger chimw.LoggerInterface) func(http.Handler) http.Handler {
	return chimw.RequestLogger(&pathOnlyLogFormatter{
		DefaultLogFormatter: chimw.DefaultLogFormatter{Logger: logger, NoColor: true},
	})
}
