package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"

	"github.com/reconquest/karma-go"
	"golang.org/x/crypto/pbkdf2"
)

type (
	CoreKDF struct {
		Iterations int
	}

	CoreHash struct {
		New  func() hash.Hash
		Size int
	}

	CoreBlock struct {
		New  func(key []byte) (cipher.Block, error)
		Size int
	}
)

type Core struct {
	KDF   CoreKDF
	Hash  CoreHash
	Block CoreBlock

	Encrypter func(block cipher.Block, iv []byte) cipher.Stream
	Decrypter func(block cipher.Block, iv []byte) cipher.Stream
}

var DefaultCore = Core{
	KDF: CoreKDF{
		Iterations: 256,
	},

	Hash: CoreHash{
		New:  sha256.New,
		Size: sha256.Size,
	},

	Block: CoreBlock{
		New:  aes.NewCipher,
		Size: aes.BlockSize,
	},

	Encrypter: cipher.NewCFBEncrypter,
	Decrypter: cipher.NewCFBDecrypter,
}

type blob struct {
	token []byte

	body []byte

	iv        []byte
	signature []byte
	payload   []byte
}

func (core *Core) blob(blob *blob) *blob {
	payload := blob.payload

	layout := []struct {
		data *[]byte
		size int
	}{
		{&blob.iv, core.Block.Size},
		{&blob.signature, core.Hash.Size},
		{&blob.payload, len(payload)},
	}

	var size int

	for _, field := range layout {
		size += field.size
	}

	if blob.body == nil {
		blob.body = make([]byte, size)
	}

	var offset int

	for _, field := range layout {
		*field.data = blob.body[offset : offset+field.size]
		offset += field.size
	}

	if payload != nil {
		copy(blob.payload, payload)
	} else {
		blob.payload = blob.body[offset:]
	}

	token := blob.token

	if len(token) < core.Block.Size {
		blob.token = make([]byte, core.Block.Size)
	} else {
		blob.token = make([]byte, len(token))
	}

	copy(blob.token, token)

	return blob
}

func (core *Core) DeriveKey(key []byte, salt []byte) []byte {
	return pbkdf2.Key(
		key, salt,
		core.KDF.Iterations,
		core.Block.Size,
		core.Hash.New,
	)
}

func (core *Core) Decrypt(
	token []byte,
	body []byte,
	master []byte,
) ([]byte, *cipher.StreamReader, error) {
	blob := core.blob(&blob{token: token, body: body})

	key := core.DeriveKey(master, blob.iv)

	block, err := core.Block.New(key)
	if err != nil {
		return nil, nil, karma.Format(err, "unable to initialize cipher block")
	}

	decrypter := core.Decrypter(block, blob.iv)

	decrypter.XORKeyStream(blob.token, blob.token)
	decrypter.XORKeyStream(blob.signature, blob.signature)

	blob.token = bytes.TrimRight(blob.token, "\x00")

	signature, err := core.Sign(blob.token, key)
	if err != nil {
		return nil, nil, err
	}

	if !hmac.Equal(signature, blob.signature) {
		return nil, nil, nil
	}

	return blob.token, &cipher.StreamReader{
		S: decrypter,
		R: bytes.NewBuffer(blob.payload),
	}, nil
}

func (core *Core) Encrypt(
	token []byte,
	payload []byte,
	master []byte,
) ([]byte, []byte, error) {
	blob := core.blob(&blob{token: token, payload: payload})

	_, err := rand.Read(blob.iv)
	if err != nil {
		return nil, nil, karma.Format(err, "unable to init random vector")
	}

	key := core.DeriveKey(master, blob.iv)

	block, err := core.Block.New(key)
	if err != nil {
		return nil, nil, err
	}

	signature, err := core.Sign(token, key)
	if err != nil {
		return nil, nil, nil
	}

	encrypter := core.Encrypter(block, blob.iv)

	encrypter.XORKeyStream(blob.token, blob.token)
	encrypter.XORKeyStream(blob.signature, signature)
	encrypter.XORKeyStream(blob.payload, blob.payload)

	return blob.token, blob.body, nil
}

func (core *Core) Sign(token []byte, key []byte) ([]byte, error) {
	signer := hmac.New(core.Hash.New, key)

	_, err := signer.Write(token)
	if err != nil {
		return nil, karma.
			Describe("token", token).
			Format(err, "unable to sign token")
	}

	return signer.Sum(nil), nil
}
