## Verdict

Confirmed. `decodeAndRun` in `job_decoder.go` runs `gob.NewDecoder(r).Decode(&job)` directly against `job`, a `Job` struct that carries the security-sensitive `IsAdmin` field. The reader passed in ultimately comes from `ProcessNextJob` in `queue_consumer.go`, which wraps the raw bytes returned by `queue.Receive()` from an external `MessageQueue` — attacker/producer-controlled data. Because gob deserialization populates every exported field present in the stream, an attacker who can place a message on the queue can set `IsAdmin: true` directly, and `runJob` later executes `job.Command` with elevated privileges based on that attacker-supplied flag. This is a deserialization-of-untrusted-data issue with a privilege-escalation consequence: the wire format is trusted to carry an authorization decision that should never come from the message itself.

## Source

`payload, err := queue.Receive()` in `ProcessNextJob` (`queue_consumer.go`) — bytes read from an external message queue, passed unmodified into `bytes.NewReader(payload)` and then into `decodeAndRun`, where `gob.NewDecoder(r).Decode(&job)` (`job_decoder.go`, the reported line) deserializes it straight into the privileged `Job` struct.

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

// jobWire is the on-the-wire shape decoded from the queue. It deliberately
// omits IsAdmin: that field is a privilege decision and must never be
// populated from untrusted, attacker-influenced message data.
type jobWire struct {
	Command  string
	Priority int
}

func decodeAndRun(r io.Reader) error {
	var wire jobWire

	// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
	if err := gob.NewDecoder(r).Decode(&wire); err != nil {
		return err
	}

	// IsAdmin is never taken from the decoded message; it is always false
	// for queue-originated jobs. Privileged execution must be granted
	// through a separate, trusted authorization path, not the payload.
	job := Job{
		Command:  wire.Command,
		Priority: wire.Priority,
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

The vulnerability is not gob itself but decoding untrusted bytes directly into a struct that mixes ordinary data (`Command`, `Priority`) with an authorization flag (`IsAdmin`). gob has no concept of field-level trust: whatever fields the sender includes get written into the target struct, so anything able to reach `queue.Receive()`'s data path can flip `IsAdmin` to `true` and gain elevated command execution.

The fix keeps the existing gob wire format — other producers/consumers of this queue are unaffected — and instead narrows what the wire format is allowed to populate. `jobWire` only has `Command` and `Priority`; there is no `IsAdmin` field for a decoder to write into, so no stream, however crafted, can set it. The real `Job.IsAdmin` is then explicitly constructed as `false` in code, meaning the only way a job would ever run as admin is through a code path that assigns that field from a trusted source (e.g. an authenticated internal caller), never from deserialized queue data. This follows the general remediation principle for CWE-502: when a fix would otherwise require changing the serialization format entirely, prefer constraining what the untrusted payload is allowed to populate instead — the format is preserved, but the privilege field is structurally unreachable from attacker-controlled input.
