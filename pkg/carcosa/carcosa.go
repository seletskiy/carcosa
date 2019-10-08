package carcosa

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"

	"github.com/reconquest/karma-go"
	"github.com/seletskiy/carcosa/pkg/carcosa/auth"
	"github.com/seletskiy/carcosa/pkg/carcosa/crypto"
)

type Secret struct {
	*cipher.StreamReader
	Token []byte

	ref ref
}

type Carcosa struct {
	core *crypto.Core
	path string
	ns   string
}

func NewDefault(path string, ns string) *Carcosa {
	return New(&crypto.DefaultCore, path, ns)
}

func New(core *crypto.Core, path string, ns string) *Carcosa {
	return &Carcosa{
		core: core,
		path: path,
		ns:   ns,
	}
}

func (carcosa *Carcosa) Add(
	token []byte,
	payload []byte,
	master []byte,
) error {
	repo, err := open(carcosa.path)
	if err != nil {
		return err
	}

	secrets, err := carcosa.list(repo, master)
	if err != nil {
		return err
	}

	for _, secret := range secrets {
		if bytes.Equal(secret.Token, token) {
			return karma.
				Describe("token", string(token)).
				Format(
					err,
					"secret with specified token already exists",
				)
		}
	}

	log.Infof("{add} secret: %s", string(token))

	token, ciphertext, err := carcosa.core.Encrypt(token, payload, master)
	if err != nil {
		return err
	}

	hash, err := repo.write(ciphertext)
	if err != nil {
		return karma.Format(err, "unable to write git object with ciphertext")
	}

	ref := ref{
		name: filepath.Join(carcosa.ns, hex.EncodeToString(token)),
		hash: hash,
	}

	err = repo.update(ref)
	if err != nil {
		return karma.
			Describe("hash", hash).
			Format(err, "unable to create ref for git object")
	}

	err = repo.update(ref.as(addition))
	if err != nil {
		return karma.
			Describe("ref", ref.name).
			Format(err, "unable to mark ref as added")
	}

	return nil
}

func (carcosa *Carcosa) Get(token []byte, master []byte) (*Secret, error) {
	repo, err := open(carcosa.path)
	if err != nil {
		return nil, err
	}

	secrets, err := carcosa.list(repo, master)
	if err != nil {
		return nil, err
	}

	for _, secret := range secrets {
		if !bytes.Equal(secret.Token, token) {
			continue
		}

		return secret, nil
	}

	return nil, nil
}

func (carcosa *Carcosa) Remove(token []byte, master []byte) error {
	secret, err := carcosa.Get(token, master)
	if err != nil {
		return err
	}

	facts := karma.Describe("token", string(token))

	if secret == nil {
		return facts.Reason("no secret found")
	}

	log.Infof("{del} secret: %s", string(token))

	repo, err := open(carcosa.path)
	if err != nil {
		return err
	}

	err = repo.delete(secret.ref)
	if err != nil {
		return facts.
			Describe("ref", secret.ref.name).
			Format(err, "unable to remove ref")
	}

	err = repo.update(secret.ref.as(deletion))
	if err != nil {
		return facts.Format(err, "unable to mark ref as deleted")
	}

	return nil
}

func (carcosa *Carcosa) Init(remote string, url string, ns string) error {
	_, err := initialize(carcosa.path, remote, url, ns)
	if err != nil {
		return karma.Format(err, "unable to initialize")
	}

	return nil
}

func (carcosa *Carcosa) Sync(
	remote string,
	auth auth.Auth,
	push bool,
) (*SyncStats, error) {
	repo, err := open(carcosa.path)
	if err != nil {
		return nil, err
	}

	stats, err := repo.Sync(remote, carcosa.ns, auth, push)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to sync",
		)
	}

	return stats, nil
}

func (carcosa *Carcosa) List(master []byte) ([]*Secret, error) {
	repo, err := open(carcosa.path)
	if err != nil {
		return nil, err
	}

	secrets, err := carcosa.list(repo, master)
	if err != nil {
		return nil, err
	}

	return secrets, nil
}

func (carcosa *Carcosa) list(repo *repo, master []byte) ([]*Secret, error) {
	refs, err := repo.list(carcosa.ns)
	if err != nil {
		return nil, karma.Format(err, "unable to list tokens")
	}

	secrets := []*Secret{}

	for _, ref := range refs {
		if ref.name != ref.token().name {
			continue
		}

		facts := karma.Describe("ref", ref.name)

		token, err := hex.DecodeString(
			strings.TrimPrefix(ref.name, carcosa.ns),
		)
		if err != nil {
			return nil, facts.
				Format(err, "unable to decode ref as hex token")
		}

		ciphertext, err := repo.cat(ref.hash)
		if err != nil {
			return nil, facts.
				Format(err, "unable to get ref contents")
		}

		token, stream, err := carcosa.core.Decrypt(token, ciphertext, master)
		if err != nil {
			return nil, facts.
				Format(err, "unable to decrypt ciphertext from ref")
		}

		// Invalid signature, possibly encrypted with another master key,
		// skipping.
		if stream == nil {
			continue
		}

		secrets = append(secrets, &Secret{
			StreamReader: stream,
			Token:        token,

			ref: ref,
		})
	}

	sort.Slice(secrets, func(i, j int) bool {
		return bytes.Compare(secrets[i].Token, secrets[j].Token) < 0
	})

	return secrets, nil
}
