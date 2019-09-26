package crypto

import (
	"bytes"
	"io/ioutil"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/rand"
	"gonum.org/v1/gonum/stat"
	"gonum.org/v1/gonum/stat/distuv"
)

func TestCore_Encrypt_Decrypt(t *testing.T) {
	test := assert.New(t)

	var (
		token   = []byte("xxx")
		key     = []byte("skeleton key")
		payload = []byte("some text")
	)

	encryptedToken, ciphertext, err := DefaultCore.Encrypt(
		token,
		payload,
		key,
	)
	test.NoError(err)

	decryptedToken, stream, err := DefaultCore.Decrypt(
		encryptedToken,
		ciphertext,
		key,
	)
	test.NoError(err)

	test.Equal(token, decryptedToken)

	decryptedPayload, err := ioutil.ReadAll(stream)
	test.NoError(err)

	test.Equal(payload, decryptedPayload)
}

func TestCore_Encrypt_Randomness_ChiSquare(t *testing.T) {
	test := assert.New(t)

	var (
		token   = []byte("xxx")
		key     = []byte("skeleton key")
		payload = bytes.Repeat([]byte("some text"), 100)
	)

	_, ciphertext, err := DefaultCore.Encrypt(
		token,
		payload,
		key,
	)
	test.NoError(err)

	observed := make([]float64, 256)
	expected := make([]float64, 256)

	for _, b := range ciphertext {
		observed[b]++
	}

	for i := range expected {
		expected[i] = float64(len(ciphertext)) / 256.0
	}

	chisq := distuv.ChiSquared{
		K:   255,
		Src: rand.NewSource(uint64(1)),
	}

	p := 0.99

	quantile := chisq.Quantile(p)

	statistic := stat.ChiSquare(observed, expected)

	// https://en.wikipedia.org/wiki/Pearson%27s_chi-squared_test
	if statistic > quantile {
		test.Failf(
			"calculated chi-square statistic exceeds critical value",
			"p=%.2f, quantile=%f, statistic=%f", p, quantile, statistic,
		)
	}
}

func TestCore_Encrypt_Randomness_Entropy(t *testing.T) {
	test := assert.New(t)

	var (
		token   = []byte("xxx")
		key     = []byte("skeleton key")
		payload = bytes.Repeat([]byte("some text"), 100)
	)

	_, ciphertext, err := DefaultCore.Encrypt(
		token,
		payload,
		key,
	)
	test.NoError(err)

	observed := make([]float64, 256)

	for _, b := range ciphertext {
		observed[b]++
	}

	entropy := 0.0

	for _, freq := range observed {
		if freq == 0 {
			continue
		}

		freq = freq / float64(len(ciphertext))

		entropy += -freq * math.Log(freq) / math.Log(256.0)
	}

	p := 0.95

	// For completely random data uncertanty about next occurrence of next byte
	// in sample will gravitate towards 100% as sample size grows.
	if entropy < p {
		test.Failf(
			"calculated entropy indicates uncertanty lower than required",
			"p=%.2f, entropy=%f", p, entropy,
		)
	}
}
