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

func decodeAndRun(r io.Reader) error {
	var job Job

	// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
	if err := gob.NewDecoder(r).Decode(&job); err != nil {
		return err
	}

	return runJob(job)
}

func runJob(job Job) error {
	// Executes job.Command with elevated privileges when job.IsAdmin is true.
	return nil
}
