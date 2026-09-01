## Verdict

Exploitable log injection confirmed. Untrusted HTTP query parameter flows directly into log message without encoding, enabling newline injection to forge log entries.

## Source

Line 10: `username := r.URL.Query().Get("username")` — untrusted HTTP query parameter with no validation.

Taint reaches sink at line 14 via direct parameter passing.

## Fix

Replace the legacy `log` package call with `log/slog` structured logging, passing the untrusted value as an attribute:

```go
// Before (line 14)
log.Printf("Failed login attempt for user: %s", username)

// After
slog.Error("Failed login attempt", slog.String("user", username))
```

Update imports:
- Remove: `"log"`
- Add: `"log/slog"`

Also update line 28 to use `slog`:
```go
// Before
log.Fatal(http.ListenAndServe(":8080", nil))

// After
slog.Error("Server failed", slog.Any("err", http.ListenAndServe(":8080", nil)))
```

## Explanation

The legacy `log.Printf` has no built-in escaping: a username containing `\n` or `\r` produces a literal newline in the log output, forging a separate entry. The `log/slog` package (Go 1.21+) handles structured attributes differently — it escapes the full ASCII control range (U+0000 to U+001F, U+007F) plus Unicode line separators in the attribute value itself. This escaping is applied by every handler type (`TextHandler`, `JSONHandler`, the default), so the injection is prevented at the sink, not dependent on choosing a specific output format. The untrusted value becomes data, not log structure.

## Behaviour changes

**Logs before fix:**
```
2024/09/01 10:30:45 Failed login attempt for user: alice
eve
injected: true
```

**Logs after fix:**
```
2024/09/01 10:30:45 level=ERROR msg="Failed login attempt" user="alice\neve\ninjected: true"
```

The escaped output preserves the attacker's input (evidence of an attack attempt) while preventing the forged entries. The log structure is intact; the malicious data appears as a literal backslash-escaped sequence in the attribute value, not as control characters. No attacker-controlled entry boundary is created.
