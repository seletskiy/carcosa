package cache

import (
	"encoding/hex"
	"io/ioutil"
	"path/filepath"

	"github.com/reconquest/karma-go"
	"github.com/seletskiy/carcosa/pkg/carcosa/crypto"
	"github.com/seletskiy/carcosa/pkg/carcosa/vault"
)

type Cache struct {
	vault vault.Vault
	core  *crypto.Core
}

func NewDefault(vault vault.Vault) *Cache {
	return New(vault, &crypto.DefaultCore)
}

func New(vault vault.Vault, core *crypto.Core) *Cache {
	return &Cache{
		vault: vault,
		core:  core,
	}
}

func (cache *Cache) Set(repo string, master []byte) error {
	token, err := cache.token(repo)
	if err != nil {
		return err
	}

	key, err := cache.vault.Key()
	if err != nil {
		return karma.Format(
			err,
			"unable to get cache vault key",
		)
	}

	name := hex.EncodeToString(token)

	token, body, err := cache.core.Encrypt(token, master, key)
	if err != nil {
		return karma.Format(
			err,
			"unable to encrypt master key",
		)
	}

	err = cache.vault.Set(name, append(token, body...))
	if err != nil {
		return karma.Format(
			err,
			"unable to store master key in vault",
		)
	}

	return nil
}

func (cache *Cache) Get(repo string) ([]byte, error) {
	token, err := cache.token(repo)
	if err != nil {
		return nil, err
	}

	key, err := cache.vault.Key()
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to get cache vault key",
		)
	}

	data, err := cache.vault.Get(hex.EncodeToString(token))
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to get encrypted master key from vault",
		)
	}

	if data == nil {
		return nil, nil
	}

	if len(data) <= cache.core.Hash.Size {
		return nil, karma.
			Describe("len", len(data)).
			Reason("encrypted master key record is too short")
	}

	token, body := data[:cache.core.Hash.Size], data[cache.core.Hash.Size:]

	token, secret, err := cache.core.Decrypt(token, body, key)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to decrypt master key",
		)
	}

	if secret == nil {
		return nil, karma.Format(
			err,
			"encrypted master key cache signature mismatch",
		)
	}

	master, err := ioutil.ReadAll(secret)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to read master key from vault",
		)
	}

	return master, nil
}

func (cache *Cache) token(path string) ([]byte, error) {
	repo, err := filepath.Abs(path)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to get absolute path to repo",
		)
	}

	hasher := cache.core.Hash.New()

	_, err = hasher.Write([]byte(repo))
	if err != nil {
		return nil, karma.
			Describe("path", path).
			Format(err, "unable to calc repo path hash")
	}

	return hasher.Sum(nil), nil
}
