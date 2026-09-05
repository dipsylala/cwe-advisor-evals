## Verdict

Exploitable. An attacker can craft a gob-encoded payload with `IsAdmin=true` to be placed in the message queue, and the deserialization at line 18 will populate this privileged field directly from untrusted data, leading to privilege escalation when `runJob()` uses it to grant elevated execution.

## Source

Untrusted data originates from `queue.Receive()` in `queue_consumer.go`, which returns a `[]byte` payload from an external message queue. This payload flows to `decodeAndRun()` via `bytes.NewReader(payload)`.

## Fix

**Vulnerable code:**

```go
func decodeAndRun(r io.Reader) error {
	var job Job

	// Deserializes untrusted data directly into full struct, including IsAdmin
	if err := gob.NewDecoder(r).Decode(&job); err != nil {
		return err
	}

	return runJob(job)
}
```

**Fixed code:**

```go
// JobRequest is the client-submitted request DTO containing only settable fields
type JobRequest struct {
	Command  string
	Priority int
}

func decodeAndRun(r io.Reader) error {
	var jobReq JobRequest

	// Deserialize into narrow DTO, not the persistence struct
	if err := gob.NewDecoder(r).Decode(&jobReq); err != nil {
		return err
	}

	// Construct Job with IsAdmin set server-side (hardcoded safe default)
	job := Job{
		Command:  jobReq.Command,
		Priority: jobReq.Priority,
		IsAdmin:  false,
	}

	return runJob(job)
}
```

## Explanation

The fix introduces a narrow request DTO (`JobRequest`) containing only the fields the client is allowed to set (`Command` and `Priority`). The gob decoder now targets this DTO instead of the full `Job` struct. After decoding, the `Job` struct is constructed explicitly, with `IsAdmin` hardcoded to `false` rather than populated from untrusted input. This prevents an attacker from setting `IsAdmin=true` via a malicious gob payload. The privileged `IsAdmin` field is now a server-controlled value that should be resolved through proper authorization checks (e.g., checking user roles in a database), not from client-submitted data. This pattern aligns with Go CWE-502 guidance: the gob format and sink remain unchanged, but the destination type is narrowed to eliminate the privilege-escalation vector.

## Behaviour changes

- A new `JobRequest` type is introduced as an intermediate deserialization target.
- The `gob.Decode()` call now targets `&jobReq` (JobRequest) instead of `&job` (Job).
- The `Job` struct is now constructed explicitly with field assignment, rather than populated by deserialization.
- `IsAdmin` is hardcoded to `false` in the constructed Job and no longer populated from the gob payload.
- The `runJob()` function still receives a fully populated `Job` struct, so its contract is unchanged; only the source of the `IsAdmin` value has changed from untrusted deserialization to server-controlled hardcoding.
