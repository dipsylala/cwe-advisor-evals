## Verdict

Exploitable. An attacker can craft a gob-serialized `Job` struct with `IsAdmin` set to `true` and send it through the message queue. The unsafe deserialization at line 18 of `job_decoder.go` will instantiate this attacker-controlled struct, granting elevated privileges without server-side authorization verification.

## Source

**Location:** `evals/cases/502/go/JobQueueGobPrivilegeField/`

**Data Flow:**
- Source: `queue.Receive()` in `queue_consumer.go:12` returns untrusted binary data
- Transit: `bytes.NewReader(payload)` at `queue_consumer.go:17` wraps untrusted data
- Sink: `gob.NewDecoder(r).Decode(&job)` at `job_decoder.go:18` deserializes the untrusted data directly into a struct containing the privileged field `IsAdmin`
- Usage: `job.IsAdmin` determines privilege level in `runJob()` at `job_decoder.go:22`

## Fix

**Vulnerable Code:**

```go
package jobs

import (
	"encoding/gob"
	"io"
)

type Job struct {
	Command  string
	Priority int
	IsAdmin  bool  // ← PROBLEM: populated from untrusted deserialized data
}

func decodeAndRun(r io.Reader) error {
	var job Job

	// ← PROBLEM: gob.Decode will instantiate and populate all fields, including IsAdmin, from untrusted data
	if err := gob.NewDecoder(r).Decode(&job); err != nil {
		return err
	}

	return runJob(job)
}

func runJob(job Job) error {
	// Executes job.Command with elevated privileges when job.IsAdmin is true.
	return nil
}
```

**Fixed Code:**

```go
package jobs

import (
	"encoding/json"
	"io"
)

type Job struct {
	Command  string
	Priority int
	IsAdmin  bool
}

// JobRequest is a narrow DTO for client input, excluding privileged fields
type JobRequest struct {
	Command  string `json:"command"`
	Priority int    `json:"priority"`
}

func decodeAndRun(r io.Reader, checkAdmin func() bool) error {
	var req JobRequest

	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields() // Reject unexpected fields to catch tampering

	if err := decoder.Decode(&req); err != nil {
		return err
	}

	// Construct Job with server-determined authorization, not client-supplied IsAdmin
	job := Job{
		Command:  req.Command,
		Priority: req.Priority,
		IsAdmin:  checkAdmin(), // Resolve IsAdmin from server-side authorization
	}

	return runJob(job)
}

func runJob(job Job) error {
	// Executes job.Command with elevated privileges when job.IsAdmin is true.
	return nil
}
```

Caller must be updated to provide the authorization check:

```go
func ProcessNextJob(queue MessageQueue, checkAdmin func() bool) error {
	payload, err := queue.Receive()
	if err != nil {
		return err
	}

	return decodeAndRun(bytes.NewReader(payload), checkAdmin)
}
```

## Explanation

The vulnerability stems from using `encoding/gob` to deserialize untrusted data directly into a struct that contains a privileged field (`IsAdmin`). The gob format will instantiate and populate all struct fields from the serialized bytes without any integrity checks or authorization verification. An attacker can craft a malicious gob payload setting `IsAdmin = true`, bypassing all access control.

The fix replaces `encoding/gob` with `encoding/json` and introduces a narrow request struct (`JobRequest`) that excludes privileged fields. This forces an explicit separation: client-supplied data goes into the request struct, while the privileged `IsAdmin` field is determined from server-side authorization via the `checkAdmin()` callback. The fixed code constructs the `Job` struct by combining validated client data with server-determined authorization, ensuring the attacker cannot control privilege levels through deserialization. `DisallowUnknownFields()` hardens the JSON decoder against attackers attempting to inject unexpected fields.

## Behaviour changes

- **Function signature change:** `decodeAndRun()` now requires a `checkAdmin func() bool` parameter to resolve authorization server-side instead of relying on client input. Callers must provide this function.
- **New type introduced:** `JobRequest` DTO separates client-supplied fields from privileged fields, making the authorization boundary explicit.
- **Serialization format change:** Switched from `encoding/gob` (binary, format-agnostic field instantiation) to `encoding/json` (text, schema-aware deserialization). This changes the wire format and requires clients to send JSON instead of gob, but provides stronger integrity and field control.
- **Field validation hardening:** `DisallowUnknownFields()` rejects payloads with unexpected fields, providing early detection of tampering attempts.
- **No changes to return values, error handling, or downstream `runJob()` contract:** The function still returns `error` and passes a `Job` struct to `runJob()` with the same signature, maintaining compatibility with the business logic layer.
