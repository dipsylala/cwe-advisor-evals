## Verdict

**CONFIRMED** - CWE-502 (Deserialization of Untrusted Data). Untrusted gob-encoded data from the message queue can set the privileged `IsAdmin` field, allowing an attacker to execute commands with elevated privileges.

## Source

**File**: `job_decoder.go`, line 18  
**Sink**: `gob.NewDecoder(r).Decode(&job)`  
**Vulnerability**: Deserializes untrusted queue data into the full `Job` struct, which includes the privileged `IsAdmin` field. No type restriction or validation prevents an attacker from crafting a malicious gob message that sets `IsAdmin = true`.

**Data flow**:
- Untrusted source: `MessageQueue.Receive()` returns arbitrary bytes
- Sink: `gob.Decode(&job)` instantiates all struct fields from the serialized data, including `IsAdmin`
- Exploitation: Attacker sends gob-encoded data with `IsAdmin: true` via the queue, gaining privilege escalation

## Fix

Create a narrow request DTO containing only client-settable fields, decode into it, and construct the `Job` explicitly with privileged fields from server-side authorization only.

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

// JobRequest is a request DTO containing only client-settable fields.
// The IsAdmin field is deliberately excluded; privilege must be determined server-side.
type JobRequest struct {
	Command  string
	Priority int
}

func decodeAndRun(r io.Reader, isAdmin bool) error {
	var jobRequest JobRequest

	// Decode into the narrow DTO. gob.Decode only populates fields present in the destination type,
	// so even if the encoded data contains IsAdmin, it will be ignored.
	if err := gob.NewDecoder(r).Decode(&jobRequest); err != nil {
		return err
	}

	// Construct the Job explicitly from validated request fields plus server-side authorization.
	// IsAdmin comes only from trusted authorization checks, never from the untrusted deserialized data.
	job := Job{
		Command:  jobRequest.Command,
		Priority: jobRequest.Priority,
		IsAdmin:  isAdmin,
	}

	return runJob(job)
}

func runJob(job Job) error {
	// Executes job.Command with elevated privileges when job.IsAdmin is true.
	return nil
}
```

### File: queue_consumer.go

```go
package jobs

import (
	"bytes"
)

type MessageQueue interface {
	Receive() ([]byte, error)
}

// checkAdminPermissions determines if the current request has admin privileges.
// In a real implementation, this retrieves the user's authorization status from a trusted source:
// - JWT token claims validated with a signing key
// - Database lookup of the user's role
// - Request context set by authentication middleware
// This is called independently of the deserialized message content.
func checkAdminPermissions() bool {
	// TODO: Replace with actual server-side authorization check (e.g., database lookup, JWT validation)
	return false
}

func ProcessNextJob(queue MessageQueue) error {
	payload, err := queue.Receive()
	if err != nil {
		return err
	}

	// Determine authorization from server-side checks, never from untrusted message data.
	isAdmin := checkAdminPermissions()

	return decodeAndRun(bytes.NewReader(payload), isAdmin)
}
```

## Explanation

The vulnerability was deserialization of untrusted `Job` objects directly from queue messages. The attacker-controlled `IsAdmin` field allowed privilege escalation: setting `IsAdmin = true` would cause `runJob()` to execute commands with elevated privileges.

The fix implements the core CWE-502 mitigation for Go: **narrow the deserialization target type to exclude privileged fields**, then **construct privileged state from server-side authorization only**.

**Changes:**
1. **Create `JobRequest` DTO**: Contains only the two client-settable fields (`Command`, `Priority`). The `IsAdmin` field is deliberately absent.
2. **Decode into DTO**: `gob.Decode()` respects the destination type's fields; it ignores any `IsAdmin` data in the encoded message because `JobRequest` has no such field.
3. **Explicit Job construction**: Build the `Job` struct from validated request fields (`jobRequest.Command`, `jobRequest.Priority`) plus `isAdmin` from `checkAdminPermissions()`, which retrieves authorization from a trusted server-side source, not from the message.
4. **Authorization decoupling**: Pass the authorization state from the caller (`ProcessNextJob`) to the decoder (`decodeAndRun`), ensuring privilege determination happens before deserialization and outside the attacker's control.

**Why this is safe:**
- `gob` only deserializes fields that exist in the target struct, so `IsAdmin` in the message is discarded.
- `IsAdmin` in the resulting `Job` object comes only from `checkAdminPermissions()`, which is a server-side function the attacker cannot manipulate through message content.
- The contract of `gob.Decode()` is unchanged: it still decodes into a concrete struct. No behavior change for legitimate payloads.

## Behaviour changes

- **Message format**: No change. Existing gob-encoded messages remain valid; `gob.Decode()` ignores the `IsAdmin` field if present.
- **Privilege determination**: Migrated from message content to server-side authorization. Legitimate callers must now pass the authorization state to `decodeAndRun()`.
- **Caller contract**: `decodeAndRun()` now requires an `isAdmin` boolean parameter. Callers like `ProcessNextJob` must retrieve this from a trusted authorization source before calling.
- **Default privilege**: In the stub implementation, `checkAdminPermissions()` defaults to `false` (least-privilege). Real implementations should replace this with actual authorization logic (JWT validation, role lookup, etc.).
- **Security impact**: Attackers can no longer escalate privileges by crafting gob messages. Privilege level is now determined exclusively by the application's authorization layer.
