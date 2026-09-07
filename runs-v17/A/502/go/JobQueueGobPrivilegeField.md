## Verdict

CONFIRMED - CWE-502 Deserialization of Untrusted Data. The `decodeAndRun` function deserializes untrusted queue data directly into a `Job` struct that includes the sensitive `IsAdmin` field. An attacker can craft a serialized payload with `IsAdmin = true` to gain privilege escalation when the deserialized job is executed.

## Source

Queue message payload flows through `ProcessNextJob` → `bytes.NewReader(payload)` → `decodeAndRun` → `gob.NewDecoder(r).Decode(&job)` at line 18 of `job_decoder.go`. The attacker controls the serialized payload from the message queue and can set any field in the `Job` struct, including the privilege field `IsAdmin`.

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

// jobPayload defines only the safe fields that can be deserialized from untrusted input.
// The IsAdmin field is intentionally excluded and will not be populated during deserialization.
type jobPayload struct {
	Command  string
	Priority int
}

func decodeAndRun(r io.Reader) error {
	var payload jobPayload

	// Deserialize only the safe fields from untrusted data
	if err := gob.NewDecoder(r).Decode(&payload); err != nil {
		return err
	}

	// Construct the Job struct with IsAdmin explicitly set to false (trusted default).
	// This prevents untrusted input from controlling the privilege field.
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

The vulnerability exists because the original code deserializes untrusted queue data directly into the complete `Job` struct, allowing an attacker to control all fields including `IsAdmin`. Since the code later uses `IsAdmin` to grant elevated privileges, an attacker can craft a malicious job object with `IsAdmin = true`.

The fix separates concerns by using a narrow deserialization struct (`jobPayload`) that excludes sensitive fields. Only safe, non-privilege-related fields (`Command` and `Priority`) are allowed to be populated from untrusted input. After deserialization, the actual `Job` struct is constructed with `IsAdmin` explicitly set to `false` under application control, preventing the privilege field from being influenced by untrusted data. This approach maintains format compatibility with legitimate producers while enforcing a deny-by-default policy for sensitive fields.

