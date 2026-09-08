## Verdict

Exploitable. Confidence: high.

- **cwe_id**: CWE-502 (Deserialization of Untrusted Data)
- **location**: `job_decoder.go`, line 18 (`gob.NewDecoder(r).Decode(&job)`)

## Source

`ProcessNextJob` (`queue_consumer.go`) reads a raw byte payload from `queue.Receive()` on a `MessageQueue` - an externally-fed message source with no integrity or authorization check applied before the bytes reach decoding - and passes it straight into `decodeAndRun` via `bytes.NewReader(payload)`.

## Fix

### File: job_decoder.go

```go
package jobs

import (
	"encoding/gob"
	"io"
)

// Job is the domain type passed to runJob. IsAdmin is a privileged field and
// must only ever be set from a server-side decision, never from decoded
// client/queue input.
type Job struct {
	Command  string
	Priority int
	IsAdmin  bool
}

// JobRequest is the wire-level type decoded from the untrusted queue
// message. It carries only the fields a producer is allowed to set; it has
// no IsAdmin field, so gob has nothing to populate from an attacker-supplied
// value even if a message includes one.
type JobRequest struct {
	Command  string
	Priority int
}

func decodeAndRun(r io.Reader) error {
	var req JobRequest

	// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
	if err := gob.NewDecoder(r).Decode(&req); err != nil {
		return err
	}

	job := Job{
		Command:  req.Command,
		Priority: req.Priority,
		IsAdmin:  false, // privileged: never derived from untrusted input; queue-submitted jobs always run unprivileged
	}

	return runJob(job)
}

func runJob(job Job) error {
	// Executes job.Command with elevated privileges when job.IsAdmin is true.
	return nil
}
```

## Explanation

The sink itself (`gob.NewDecoder(r).Decode(...)`) is unchanged - `encoding/gob` is Go's standard library wire format and the queue producer is outside this change, so the fix keeps the format rather than swapping it. What moves is the destination type: the decoder now populates `JobRequest`, a narrow struct containing only `Command` and `Priority`, instead of the `Job` domain struct that also carries `IsAdmin`. `gob` matches fields by name and silently drops any field present in the input but absent from the destination type, so even a queue message that includes an `IsAdmin` value has nothing to decode into - the field is discarded before it ever reaches application logic. The `Job` passed to `runJob` is then built explicitly, with `IsAdmin` hard-set to `false` rather than copied from anything attacker-influenced. No authorization/database lookup exists anywhere in this call chain to source a legitimate privileged value from, so `false` is the only safe default; a system that needs to run admin jobs must add an explicit, trusted mechanism for that determination.

## Behaviour changes

- `IsAdmin` on the resulting `Job` is now always `false`, regardless of what the queue payload's `gob`-encoded bytes previously set it to. Before the fix, any producer able to write to the queue could set `IsAdmin: true` and get elevated execution in `runJob`; after the fix, no queue message can select the admin path at all. If some legitimate internal producer relied on setting `IsAdmin: true` through this same queue to schedule real admin jobs, that capability is removed until a proper trusted-side authorization path is added - this is the intended effect of closing the weakness, not an incidental change.
- `decodeAndRun`'s error behaviour is unchanged: `gob.Decode` still returns the same decode error on malformed input, and `runJob`'s return value is passed through exactly as before.
- No change to `queue_consumer.go`; it is included above only for context and was not modified.

**Verification**: `go vet ./...` and `go build ./...` were run against the fixed `job_decoder.go` plus the unmodified `queue_consumer.go` in a scratch module outside the case directory; both completed with no errors or warnings, confirming the new `JobRequest` type and the rewritten `decodeAndRun` compile and pass static checks.

**Assumptions**: No server-side authorization/database lookup for `IsAdmin` exists anywhere in the provided call chain, so the fix hard-codes `false` rather than resolving a real privileged value, per the Go guidance's instruction to source privileged fields from server-side authorization rather than the request. This is stated as a behaviour change above rather than treated as a hidden feature loss.
