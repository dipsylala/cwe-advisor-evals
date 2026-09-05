## Verdict
Exploitable

## Source
The `mux` variable containing registered handlers, built in `buildMux()` and assigned at line 22, includes a state-changing handler `POST /settings` (line 16).

## Fix

**Vulnerable code:**
```go
// Line 34-38: HTTP listener serves the full, unprotected mux
go func() {
	log.Println("starting plaintext listener on :8080")
	// SAST FINDING: CWE-352 reported here
	log.Fatal(http.ListenAndServe(":8080", mux))
}()
```

**Fixed code:**
```go
// Create a redirect-only mux for the HTTP listener
redirectMux := http.NewServeMux()
redirectMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	target := r.URL
	target.Scheme = "https"
	target.Host = r.Host
	http.Redirect(w, r, target.String(), http.StatusMovedPermanently)
})

go func() {
	log.Println("starting plaintext listener on :8080")
	log.Fatal(http.ListenAndServe(":8080", redirectMux))
}()
```

## Explanation
The original code inadvertently serves the entire application (including the CSRF-unprotected mux) on the HTTP listener. This exposes the state-changing `POST /settings` endpoint to cross-origin attacks without CSRF token validation. The fix creates a separate redirect-only mux for the HTTP listener that redirects all requests to HTTPS, ensuring state-changing handlers are only reachable through the CSRF-protected HTTPS listener. This aligns with the Go CWE-352 guidance: "Ensure every handler that mutates state is registered on the CSRF-wrapped router, not a separate `http.ServeMux` or parallel API mux."

## Behaviour changes
- HTTP listener now redirects all requests to HTTPS using HTTP 301 (Moved Permanently) instead of serving the application directly
- No state-changing operations are accessible over plaintext HTTP
- Legitimate users are transparently redirected to the secure listener; all requests that previously succeeded on HTTP now succeed on HTTPS instead
- The redirect preserves the request path and query string, so links from email notifications or bookmarks to `http://...` still reach the correct HTTPS endpoint
