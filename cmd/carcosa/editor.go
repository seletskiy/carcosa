package main

import (
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/reconquest/karma-go"
)

func editor(command string, plaintext []byte) ([]byte, error) {
	buffer, err := ioutil.TempFile(os.TempDir(), "carcosa.secret.")
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to create temporary file",
		)
	}

	facts := karma.Describe("name", buffer.Name())

	err = buffer.Chmod(0600)
	if err != nil {
		return nil, facts.Format(
			err,
			"unable to chmod 0600 the temporary file",
		)
	}

	_, err = buffer.Write(plaintext)
	if err != nil {
		return nil, facts.Format(
			err,
			"unable to write data to the temporary file",
		)
	}

	err = buffer.Sync()
	if err != nil {
		return nil, facts.Format(
			err,
			"unable to sync data to the temporary file",
		)
	}

	facts = facts.Describe("command", command)

	cmd := exec.Command(command, buffer.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		return nil, facts.Format(
			err,
			"editor exited with error",
		)
	}

	_, err = buffer.Seek(0, 0)
	if err != nil {
		return nil, facts.Format(
			err,
			"unable to seek to the beginning of the temporary file",
		)
	}

	plaintext, err = ioutil.ReadAll(buffer)
	if err != nil {
		return nil, facts.Format(
			err,
			"unable to read temporary file",
		)
	}

	return plaintext, nil
}
