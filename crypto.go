package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/seletskiy/hierr"
)

type secret struct {
	token  string
	hash   string
	ref    ref
	stream cipher.StreamReader
}

type blob struct {
	HMAC  func() hash.Hash
	block cipher.Block
	body  []byte
}

func (data *blob) init(plaintext []byte) {
	data.body = make(
		[]byte,
		data.getBlockSize()+data.getHMACSize()+len(plaintext),
	)
}

func (data *blob) getBody() []byte {
	return data.body
}

func (data *blob) getBlockSize() int {
	return data.block.BlockSize()
}

func (data *blob) getHMACSize() int {
	return data.HMAC().Size()
}

func (data *blob) getInitVector() []byte {
	return data.body[:data.getBlockSize()]
}

func (data *blob) getTokenHMAC() []byte {
	offset := data.getBlockSize()

	return data.body[offset : offset+data.getHMACSize()]
}

func (data *blob) getPlaintext() []byte {
	return data.body[data.getBlockSize()+data.getHMACSize():]
}

var (
	errInvalidHMAC = fmt.Errorf("HMAC is not valid")

	newHMAC   = sha256.New
	newCipher = aes.NewCipher
)

func decryptBlob(token []byte, body []byte, key []byte) (*secret, error) {
	blockCipher, err := newCipher(key)
	if err != nil {
		return nil, hierr.Errorf(err, "can't initialize AES")
	}

	ciphertext := blob{
		HMAC:  newHMAC,
		block: blockCipher,
		body:  body,
	}

	decrypter := cipher.NewCFBDecrypter(
		blockCipher, ciphertext.getInitVector(),
	)

	paddedToken := make([]byte, len(token))
	decrypter.XORKeyStream(paddedToken, token)

	tokenMAC := make([]byte, ciphertext.getHMACSize())
	decrypter.XORKeyStream(tokenMAC, ciphertext.getTokenHMAC())

	decryptedToken := unpadBytes(paddedToken)
	expectedTokenMAC, err := calcHMAC(ciphertext.HMAC, decryptedToken, key)

	if err != nil {
		return nil, err
	}

	if !hmac.Equal(expectedTokenMAC, tokenMAC) {
		return nil, errInvalidHMAC
	}

	return &secret{
		hash:  hex.EncodeToString(token),
		token: string(decryptedToken),
		stream: cipher.StreamReader{
			S: decrypter,
			R: bytes.NewBuffer(ciphertext.getPlaintext()),
		},
	}, nil
}

func encryptBlob(
	token []byte, plaintext []byte, key []byte,
) (encryptedToken []byte, ciphertext *blob, err error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, hierr.Errorf(err, "can't initialize AES")
	}

	ciphertext = &blob{
		HMAC:  sha256.New,
		block: blockCipher,
	}

	ciphertext.init(plaintext)

	if _, err = rand.Read(ciphertext.getInitVector()); err != nil {
		return nil, nil, hierr.Errorf(err, "can't create IV for cipher")
	}

	paddedToken := padBytes([]byte(token), blockCipher.BlockSize())

	encrypter := cipher.NewCFBEncrypter(
		blockCipher, ciphertext.getInitVector(),
	)

	encryptedToken = make([]byte, len(paddedToken))
	encrypter.XORKeyStream(encryptedToken, paddedToken)

	tokenMAC, err := calcHMAC(ciphertext.HMAC, token, key)
	if err != nil {
		return nil, nil, err
	}

	encrypter.XORKeyStream(ciphertext.getTokenHMAC(), tokenMAC)
	encrypter.XORKeyStream(ciphertext.getPlaintext(), plaintext)

	return encryptedToken, ciphertext, nil
}

func calcHMAC(
	hasher func() hash.Hash, token []byte, masterKey []byte,
) ([]byte, error) {
	mac := hmac.New(hasher, masterKey)

	_, err := mac.Write(token)
	if err != nil {
		return nil, hierr.Errorf(
			err,
			"can't calculate HMAC for token '%s'", token,
		)
	}

	return mac.Sum(nil), nil
}

func unpadBytes(source []byte) []byte {
	return bytes.TrimRight(source, "\x00")
}

func padBytes(source []byte, length int) []byte {
	if len(source) >= length {
		return source
	}

	result := make([]byte, length)

	copy(result, source)

	return result
}

func padBytesToBlockKey(source []byte) ([]byte, error) {
	switch {
	case len(source) < 16:
		return padBytes(source, 16), nil
	case len(source) < 24:
		return padBytes(source, 24), nil
	case len(source) < 32:
		return padBytes(source, 32), nil
	default:
		return nil, fmt.Errorf("key is too long (max 32 bytes)")
	}
}
