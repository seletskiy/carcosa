package vault

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/reconquest/karma-go"
	"github.com/seletskiy/carcosa/pkg/carcosa"
)

type Vault interface {
	Key() ([]byte, error)
	Get(token string) ([]byte, error)
	Set(token string, body []byte) error
}

type Master struct {
	tokensDir string
	keyPath   string
}

func NewMaster(tokensDir string, keyPath string) *Master {
	return &Master{
		tokensDir: tokensDir,
		keyPath:   keyPath,
	}
}

func (master *Master) Key() ([]byte, error) {
	machineID, err := ioutil.ReadFile(master.keyPath)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to read encryption key file",
		)
	}

	return bytes.TrimSpace(machineID), nil
}

func (master *Master) Get(token string) ([]byte, error) {
	carcosa.Logger().Debugf("reading master-key file: %s", master.file(token))

	body, err := ioutil.ReadFile(master.file(token))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, err
	}

	return body, nil
}

func (master *Master) Set(token string, body []byte) error {
	err := os.MkdirAll(master.tokensDir, 0700)
	if err != nil {
		return karma.
			Describe("dir", master.tokensDir).
			Format(err, "unable to create dir for storing master key cache")
	}

	carcosa.Logger().Debugf("writing master-key file: %s", master.file(token))

	err = ioutil.WriteFile(master.file(token), body, 0600)
	if err != nil {
		return err
	}

	return nil
}

func (master *Master) file(token string) string {
	return filepath.Join(master.tokensDir, token+".key")
}
