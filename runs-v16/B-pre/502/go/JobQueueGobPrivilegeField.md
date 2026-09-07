## Verdict

exploitable

## Source

Untrusted data enters via `queue.Receive()` at line 12 of `queue_consumer.go`, passed as a byte slice to `decodeAndRun()`, which deserializes it at line 18 of `job_decoder.go` using `gob.NewDecoder(r).Decode(&job)`. The attacker-controlled payload can set the `IsAdmin` bool field, which is then used by `runJob()` to determine whether to execute commands with elevated privileges.

## Fix

Create a narrower request struct that excludes privileged fields, and decode untrusted data into that DTO instead of the full `Job` struct. Resolve the `IsAdmin` field server-side.

**Vulnerable code:**
```go
type Job struct {
	Command  string
	Priority int
	IsAdmin  bool
}

func decodeAndRun(r io.Reader) error {
	var job Job

	// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
	if err := gob.NewDecoder(r).Decode(&job); err != nil {
		return err
	}

	return runJob(job)
}
```

**Fixed code:**
```go
type Job struct {
	Command  string
	Priority int
	IsAdmin  bool
}

// JobRequest is a narrower DTO containing only client-settable fields
type JobRequest struct {
	Command  string
	Priority int
}

func decodeAndRun(r io.Reader) error {
	var req JobRequest

	if err := gob.NewDecoder(r).Decode(&req); err != nil {
		return err
	}

	// Construct the job with server-determined privilege level
	job := Job{
		Command:  req.Command,
		Priority: req.Priority,
		IsAdmin:  false, // Never trust client data for privileged fields
	}

	return runJob(job)
}
```

## Explanation

The vulnerability allows an attacker to craft a gob-encoded payload that sets `IsAdmin` to `true`, granting unauthorized privileges. The fix creates a narrower `JobRequest` struct containing only the client-settable fields (`Command` and `Priority`), explicitly excluding the privileged `IsAdmin` field. By decoding untrusted data into this narrower struct instead of the full `Job`, gob will ignore any `IsAdmin` value present in the payload—gob only populates fields that exist in the destination type. The `IsAdmin` field is then set explicitly server-side based on authorization logic rather than client input, breaking the attack vector and ensuring privileged decisions are never influenced by untrusted deserialized data.

## Behaviour changes

- Adds a new `JobRequest` struct type as the decode destination for untrusted data
- Explicitly constructs the `Job` struct after decoding, rather than populating it directly during deserialization
- Sets `IsAdmin` to `false` server-side as a default; if elevated privileges are required, they must be determined by server-side authorization logic (e.g., via a permission check not shown in this excerpt) and assigned to the `job` before calling `runJob()`
- The `runJob()` function's input contract is unchanged—it still receives a fully initialized `Job` struct
- Any `IsAdmin` field in the incoming gob payload is silently ignored by the decoder, since `JobRequest` does not define that field
