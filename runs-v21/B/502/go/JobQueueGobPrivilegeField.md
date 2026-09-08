## Verdict

Exploitable. Untrusted gob-encoded data from the message queue flows directly into `gob.NewDecoder().Decode()` on line 18 of `job_decoder.go`, deserializing the complete `Job` struct including the privileged `IsAdmin` field. An attacker can craft gob data that sets `IsAdmin = true`, which grants elevated privileges in `runJob()`. The data source (`ProcessNextJob()` receives untrusted bytes from `MessageQueue.Receive()`) and sink are confirmed; no validation blocks the taint path.

## Source

Untrusted data originates in `queue_consumer.go` at line 12: `payload, err := queue.Receive()`. The `MessageQueue` interface has no trust boundary or validation—it is a generic queue consumer meant to read from an untrusted message broker. The payload flows through `decodeAndRun(bytes.NewReader(payload))` to the gob sink.

## Fix

### File: job_decoder.go

```go
package jobs

import (
	"encoding/gob"
	"io"
)

type Job struct {
	Command  string
	Priority int
	IsAdmin  bool
}

// JobRequest is a narrowly-typed DTO for deserialization from untrusted sources.
// It excludes privileged fields like IsAdmin, which must be determined server-side.
type JobRequest struct {
	Command  string
	Priority int
}

func decodeAndRun(r io.Reader) error {
	var req JobRequest

	// Decode into narrow request struct to prevent untrusted data from setting IsAdmin
	if err := gob.NewDecoder(r).Decode(&req); err != nil {
		return err
	}

	job := Job{
		Command:  req.Command,
		Priority: req.Priority,
		IsAdmin:  false, // Determine server-side; never trust client-supplied value
	}

	return runJob(job)
}

func runJob(job Job) error {
	// Executes job.Command with elevated privileges when job.IsAdmin is true.
	return nil
}
```

## Explanation

The fix creates a narrow request DTO (`JobRequest`) that contains only client-settable fields (`Command` and `Priority`), excluding the privileged `IsAdmin` field. The `Decode()` call now targets `JobRequest` instead of the full `Job` struct. Go's gob decoder ignores fields in the wire format that are not present in the destination type, so any `IsAdmin` value the attacker supplies is discarded. After decoding, `decodeAndRun()` explicitly constructs the `Job` struct, setting `IsAdmin = false` unconditionally—the privileged field is now determined server-side (or hardcoded safe), not from untrusted input. This closes the CWE-502 weakness by ensuring untrusted deserialization cannot populate sensitive fields.

## Behaviour changes

The `IsAdmin` field is now always `false` instead of reading its value from the gob-encoded message. This is an intentional security change: the privilege level must be determined by server-side logic (authorization checks, database lookups, role assignments), not by client data. The `decodeAndRun()` function signature and return type are unchanged; `runJob()` receives a `Job` struct with the same fields and type as before. Existing message queue producers do not need to change—the gob format they send is unchanged, and the decoder silently ignores the `IsAdmin` field they may have included. If `runJob()` previously relied on `IsAdmin` being read from the message, that is a logic error that must be fixed separately in `runJob()` by resolving admin status through a server-side authorization check (e.g., `checkAdminPermissions(ctx)` or a database lookup).
