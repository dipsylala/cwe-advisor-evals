package jobs

import (
	"bytes"
)

type MessageQueue interface {
	Receive() ([]byte, error)
}

func ProcessNextJob(queue MessageQueue) error {
	payload, err := queue.Receive()
	if err != nil {
		return err
	}

	return decodeAndRun(bytes.NewReader(payload))
}
