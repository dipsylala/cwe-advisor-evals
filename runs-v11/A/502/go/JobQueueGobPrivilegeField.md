## Verdict

The deserialization of untrusted gob-encoded data directly into a struct containing a privilege flag (`IsAdmin`) is a CWE-502 vulnerability. An attacker can craft a malicious payload that sets `IsAdmin` to `true`, granting unauthorized elevated privileges for command execution.

## Source

The vulnerability originates in `ProcessNextJob()` where untrusted message queue data flows directly to `decodeAndRun()`, which deserializes it without validation:

```
MessageQueue.Receive() → untrusted bytes → decodeAndRun(bytes.NewReader(payload)) → gob.Decode(&job) → runJob(job)
```

The `Job` struct's `IsAdmin` field, deserialized from untrusted input, directly controls whether `job.Command` executes with elevated privileges in `runJob()`.

## Fix

Separate privilege determination from deserialization. The `Job` struct should not deserialize `IsAdmin` from untrusted input. Instead, deserialize only the command and priority, and determine admin status from a trusted source:

```go
type Job struct {
	Command  string
	Priority int
	// Removed IsAdmin from struct—never deserialize privilege flags
}

func decodeAndRun(r io.Reader) error {
	var job Job

	if err := gob.NewDecoder(r).Decode(&job); err != nil {
		return err
	}

	// IsAdmin is false by default; determine from trusted source if needed
	return runJob(job)
}

func runJob(job Job) error {
	// Command executes without elevated privileges by default
	// If elevation is required, check a trusted authorization source (e.g., ACL, role store)
	// Example: isAdmin := authService.IsAdminForCommand(job.Command)
	return nil
}
```

Alternatively, if the message must carry an `IsAdmin` indicator, authenticate and sign the message with HMAC or a similar mechanism, and validate the signature before deserializing:

```go
import "crypto/hmac"
import "crypto/sha256"

func decodeAndRun(r io.Reader, signature []byte, sharedKey []byte) error {
	// Read payload
	payload, _ := io.ReadAll(r)
	
	// Validate signature before deserializing
	expectedMAC := hmac.New(sha256.New, sharedKey)
	expectedMAC.Write(payload)
	if !hmac.Equal(signature, expectedMAC.Sum(nil)) {
		return errors.New("invalid signature")
	}

	var job Job
	if err := gob.NewDecoder(bytes.NewReader(payload)).Decode(&job); err != nil {
		return err
	}

	return runJob(job)
}
```

## Explanation

CWE-502 arises when untrusted input is deserialized into objects that control security decisions. The `IsAdmin` field determines whether commands execute with elevated privileges. By removing this field from the deserialized struct, we ensure that privilege elevation cannot be triggered by attacker-supplied data.

If the privilege flag must be transmitted, cryptographic message authentication (HMAC) proves the message originates from a trusted sender before deserialization occurs. This prevents an attacker from forging a payload that sets `IsAdmin` to `true`.

The fix applies two security principles: (1) never deserialize privilege flags from untrusted sources, and (2) authenticate messages before trusting their content.
