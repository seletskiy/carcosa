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

	"golang.org/x/crypto/pbkdf2"

	"github.com/seletskiy/hierr"
)

const (
	kdfIterations = 256
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

func (data *blob) init(
	initVector []byte,
	cipher cipher.Block,
	plaintext []byte,
) {
	data.block = cipher

	data.body = make(
		[]byte,
		data.getBlockSize()+data.getHMACSize()+len(plaintext),
	)

	copy(data.getInitVector(), initVector)
}

func (data *blob) getBody() []byte {
	return data.body
}

func (data *blob) getBlockSize() int {
	return cipherBlockSize
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

	newHMAC = sha256.New

	newCipher       = aes.NewCipher
	cipherBlockSize = aes.BlockSize
)

func decryptBlob(token []byte, body []byte, password []byte) (*secret, error) {
	ciphertext := blob{
		HMAC: newHMAC,
		body: body,
	}

	key := deriveKey(password, ciphertext.getInitVector())

	blockCipher, err := newCipher(key)
	if err != nil {
		return nil, hierr.Errorf(err, "can't initialize AES")
	}

	ciphertext.block = blockCipher

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
	token []byte, plaintext []byte, password []byte,
) (encryptedToken []byte, ciphertext *blob, err error) {
	ciphertext = &blob{
		HMAC: sha256.New,
	}

	initVector := make([]byte, cipherBlockSize)

	if _, err = rand.Read(initVector); err != nil {
		return nil, nil, hierr.Errorf(err, "can't create IV for cipher")
	}

	key := deriveKey(password, initVector)

	blockCipher, err := newCipher(key)
	if err != nil {
		return nil, nil, hierr.Errorf(err, "can't initialize AES")
	}

	ciphertext.init(initVector, blockCipher, plaintext)

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

func deriveKey(key []byte, salt []byte) []byte {
	return pbkdf2.Key(key, salt, kdfIterations, cipherBlockSize, sha256.New)
}
