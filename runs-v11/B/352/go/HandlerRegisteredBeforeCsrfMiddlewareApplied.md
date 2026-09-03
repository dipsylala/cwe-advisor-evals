## Verdict

Real issue. The state-changing POST /settings handler is reachable over the unprotected HTTP listener on port 8080, bypassing all CSRF protection applied to the HTTPS listener.

## Source

Port 8080's listener (`http.ListenAndServe(":8080", mux)`) on line 37 receives the unprotected ServeMux that includes all application routes, including state-changing endpoints. The CSRF protection wraps only the HTTPS listener on port 8443.

## Fix

Replace line 37 with a redirect handler that forwards all HTTP traffic to HTTPS, preventing state-changing requests from being processed over the unprotected listener:

```go
redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.RequestURI
	http.Redirect(w, r, target, http.StatusMovedPermanently)
})

go func() {
	log.Println("starting plaintext listener on :8080")
	log.Fatal(http.ListenAndServe(":8080", redirectHandler))
}()
```

The fix ensures that:
1. The plaintext HTTP listener serves only redirect responses
2. All requests (including state-changing ones) are redirected to the HTTPS endpoint
3. Only the HTTPS listener serves content, and it does so through the CSRF-protected handler

## Explanation

The vulnerability occurs because the HTTP listener serves the same unprotected mux that the code intended to use only for redirects. Go's `net/http.CrossOriginProtection` (or similar CSRF middleware) guards only the handler it wraps, not other handlers serving the same routes. When a separate listener serves the same routes without that protection, attackers can forge CSRF requests to the unprotected HTTP endpoint. The fix creates a minimal redirect handler for the HTTP port so that all traffic—including state-changing requests—reaches only the CSRF-protected HTTPS listener.

## Behaviour changes

- HTTP requests to port 8080 now receive 301 (Moved Permanently) redirects to equivalent HTTPS URLs
- State-changing operations (POST /settings) can no longer complete over plaintext HTTP
- Clients must follow the redirect to HTTPS and pass through CSRF validation
- No functional change to HTTPS behavior; CSRF protection remains active on port 8443
