## Verdict

The code deserializes untrusted gob data directly into a `Job` struct that contains an `IsAdmin` privilege field. An attacker can craft a malicious gob message with `IsAdmin: true`, gaining unauthorized elevated privileges when the job is executed.

## Source

CWE-502: Deserialization of Untrusted Data

**Location:** `job_decoder.go`, line 18 (gob.NewDecoder sink)

**Call chain:** `ProcessNextJob` (queue_consumer.go:11) receives untrusted bytes from a message queue → passes to `decodeAndRun` (job_decoder.go:14) → deserializes directly into `Job` struct with sensitive `IsAdmin` field → `runJob` (job_decoder.go:25) executes with attacker-controlled privilege level.

**Root cause:** The gob decoder reconstructs all struct fields from untrusted input, including `IsAdmin`, which controls privilege escalation in `runJob`.

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

// Intermediate struct for safe deserialization - contains only non-privileged fields
type jobPayload struct {
	Command  string
	Priority int
}

func decodeAndRun(r io.Reader) error {
	var payload jobPayload

	// Deserialize only into safe fields
	if err := gob.NewDecoder(r).Decode(&payload); err != nil {
		return err
	}

	// Construct Job with IsAdmin always false - never trusts attacker input
	job := Job{
		Command:  payload.Command,
		Priority: payload.Priority,
		IsAdmin:  false,
	}

	return runJob(job)
}

func runJob(job Job) error {
	// Executes job.Command with elevated privileges when job.IsAdmin is true.
	return nil
}
```

## Explanation

The fix uses an intermediate deserialization struct (`jobPayload`) that contains only the safe, non-privileged fields from the serialized message. The gob decoder is directed to `jobPayload` instead of `Job`, preventing the attacker's `IsAdmin` field from ever reaching the Job struct.

After deserialization, the code explicitly constructs a `Job` with `IsAdmin` hardcoded to `false`, ensuring that privilege escalation can only occur through authenticated channels (not through malicious deserialization).

This approach:
- **Preserves format:** The gob wire protocol remains unchanged; queue producers and existing messages still work.
- **Closes the injection:** The sensitive field cannot be set by deserialized data.
- **Maintains functionality:** Legitimate command and priority fields are still accepted.
- **Fails safely:** Any attempt to inject privilege via gob is silently rejected (the field is ignored), making the attack obvious during testing rather than silently enabling escalation.
