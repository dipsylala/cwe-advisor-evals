## Verdict

Exploitable. Untrusted gob-serialized data from a message queue is deserialized directly into a `Job` struct that carries the privileged field `IsAdmin`, allowing an attacker to set admin privileges by crafting a malicious message payload.

## Source

Untrusted message payload received from `MessageQueue.Receive()` in `queue_consumer.go`, passed to `decodeAndRun()` in `job_decoder.go`.

## Fix

**Vulnerable code** (line 14–22 in job_decoder.go):

```go
func decodeAndRun(r io.Reader) error {
	var job Job

	// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
	if err := gob.NewDecoder(r).Decode(&job); err != nil {
		return err
	}

	return runJob(job)
}
```

**Fixed code**:

```go
// JobRequest is a narrow DTO containing only client-settable fields.
// It excludes privileged fields like IsAdmin, preventing an attacker from setting them via deserialization.
type JobRequest struct {
	Command  string
	Priority int
}

func decodeAndRun(r io.Reader) error {
	var req JobRequest

	if err := gob.NewDecoder(r).Decode(&req); err != nil {
		return err
	}

	// Construct the domain Job from the request, with IsAdmin determined server-side.
	job := Job{
		Command:  req.Command,
		Priority: req.Priority,
		IsAdmin:  false, // Never trust the deserialized value; determine via server-side authorization
	}

	return runJob(job)
}
```

## Explanation

The fix introduces a narrow request DTO (`JobRequest`) that contains only fields the client is allowed to set (`Command`, `Priority`), excluding the privileged `IsAdmin` field. The existing `gob.Decoder` continues to work unchanged—`Decode` into a narrower struct type silently ignores extra fields in the payload and never instantiates missing fields. By decoding into `JobRequest` instead of the domain `Job` struct, the attacker cannot inject an `IsAdmin` value into the deserialized data. The `Job` struct is then constructed explicitly server-side, with `IsAdmin` hardcoded to `false` and determined through proper authorization logic (e.g., a database lookup or permission check) rather than trusting the untrusted deserialized value. This pattern prevents the privilege-escalation vector while preserving backward compatibility with existing message producers—no wire format change is required.

## Behaviour changes

- **New type (`JobRequest`)**: A narrower DTO is introduced. This is a code-level change only; the gob wire format is unchanged and existing message producers continue to work.
- **IsAdmin always false after deserialization**: The fixed code hardcodes `IsAdmin = false` in the constructor. A proper remediation would replace this with a server-side authorization check (e.g., `IsAdmin: checkAdminPermissions(ctx)`); the hardcoded value shown here is safe and prevents the injection, but production code should resolve admin status from an authenticated user session, database lookup, or authorization service.
- **No change to error handling or return contract**: The function signature and failure behavior remain unchanged.
