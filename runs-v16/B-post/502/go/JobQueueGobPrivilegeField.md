## Verdict

CONFIRMED - Deserialization of Untrusted Data (CWE-502)

## Source

`queue_consumer.go` line 17: Untrusted `[]byte` payload from message queue is passed to `decodeAndRun()` → `job_decoder.go` line 18: gob decoder instantiates `Job` struct with untrusted `IsAdmin` field.

## Fix

**In job_decoder.go, replace the deserialization pattern to use a narrow request struct:**

```go
package jobs

import (
	"encoding/gob"
	"io"
)

// JobRequest carries only client-settable fields; privileged fields are never included
type JobRequest struct {
	Command  string
	Priority int
}

type Job struct {
	Command  string
	Priority int
	IsAdmin  bool
}

func decodeAndRun(r io.Reader) error {
	var jobReq JobRequest

	// Decode into narrow request struct; gob ignores extra encoded fields
	if err := gob.NewDecoder(r).Decode(&jobReq); err != nil {
		return err
	}

	// Reconstruct Job with server-side IsAdmin resolution
	job := Job{
		Command:  jobReq.Command,
		Priority: jobReq.Priority,
		IsAdmin:  false, // Privilege determination must come server-side (e.g., from context or DB)
	}

	return runJob(job)
}

func runJob(job Job) error {
	// Executes job.Command with elevated privileges when job.IsAdmin is true.
	return nil
}
```

## Explanation

The vulnerability allows an attacker to set arbitrary struct fields during gob deserialization. By including `IsAdmin` in the untrusted payload, an attacker can grant themselves elevated privileges. The fix applies the Go guidance's primary remediation: change the deserialization destination type from the full domain struct (`Job`) to a narrow request struct (`JobRequest`) that contains only fields the client is allowed to set. The gob decoder will ignore extra fields encoded in the payload and only populate the destination struct's fields. After decoding, construct the full `Job` struct explicitly, setting `IsAdmin` from a server-side authority (authorization context, database lookup, or hardcoded safe default) rather than untrusted client data. This breaks the taint chain at the point of reconstruction.

## Behaviour changes

- The wire format remains unchanged (gob-serialized messages from producers are still accepted).
- Extra fields in the serialized payload are silently ignored (gob default behavior when they do not exist in the destination type).
- `IsAdmin` can no longer be controlled by the message sender; it is determined exclusively by server-side logic.
- No breaking change to producers: they continue sending gob-encoded `Job` structures; the decoder simply ignores the `IsAdmin` field they may have included.
