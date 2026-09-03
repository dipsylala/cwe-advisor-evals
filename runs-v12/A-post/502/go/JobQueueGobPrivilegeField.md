## Verdict
The finding is correct. The gob decoder deserializes untrusted data into a Job struct that includes an IsAdmin field, which controls execution privileges. An attacker can craft a malicious gob-encoded payload to set IsAdmin to true, achieving privilege escalation.

## Source
The vulnerability exists in `job_decoder.go` at line 18 in the `decodeAndRun` function:
```go
if err := gob.NewDecoder(r).Decode(&job); err != nil {
```

The untrusted data flows from `ProcessNextJob` (which receives a payload from an external message queue) through `decodeAndRun`, where the gob decoder deserializes it directly into a Job struct. The Job struct's IsAdmin field is a privilege indicator that an attacker can control through the serialized payload.

## Fix
Remove the IsAdmin field from the struct used for deserialization. Create a separate struct for untrusted input that omits privilege fields, then construct the final Job object with privilege information only from trusted sources:

```go
package jobs

import (
	"encoding/gob"
	"io"
)

// JobRequest is used only for deserialization from untrusted sources.
// It explicitly omits privilege fields.
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

	// Deserialize only non-sensitive fields
	if err := gob.NewDecoder(r).Decode(&jobReq); err != nil {
		return err
	}

	// Construct Job with IsAdmin from a trusted source, never from deserialized data
	job := Job{
		Command:  jobReq.Command,
		Priority: jobReq.Priority,
		IsAdmin:  false, // Always false unless set via trusted authentication/authorization
	}

	return runJob(job)
}

func runJob(job Job) error {
	// Executes job.Command with elevated privileges when job.IsAdmin is true.
	return nil
}
```

## Explanation
CWE-502 (Deserialization of Untrusted Data) occurs when an application deserializes data from an untrusted source without validating that the resulting object's state is safe. Here, the attacker controls the serialized gob payload and can set IsAdmin to true.

The fix applies two principles:

1. **Separate untrusted deserialization from privilege modeling**: JobRequest contains only the business data fields (Command, Priority) and omits all security-sensitive fields. This ensures the deserializer has no way to set IsAdmin from the wire format.

2. **Set privilege flags only from trusted sources**: After deserialization succeeds, the IsAdmin field is set explicitly to false or determined through a separate, authenticated authorization mechanism—never from the deserialized payload.

This prevents an attacker from escalating privileges by crafting a malicious gob-encoded message, even if they can write to the message queue.
