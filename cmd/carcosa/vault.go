package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/reconquest/karma-go"
)

type vault struct {
	path string
}

func (vault *vault) Key() ([]byte, error) {
	machineID, err := ioutil.ReadFile("/etc/machine-id")
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to read machine id",
		)
	}

	return bytes.TrimSpace(machineID), nil
}

func (vault *vault) Get(token string) ([]byte, error) {
	body, err := ioutil.ReadFile(vault.file(token))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, err
	}

	return body, nil
}

func (vault *vault) Set(token string, body []byte) error {
	err := os.MkdirAll(vault.path, 0700)
	if err != nil {
		return karma.
			Describe("path", vault.path).
			Format(err, "unable to create dir for storing master key cache")
	}

	err = ioutil.WriteFile(vault.file(token), body, 0600)
	if err != nil {
		return err
	}

	return nil
}

func (vault *vault) file(token string) string {
	return filepath.Join(vault.path, token+".key")
}
