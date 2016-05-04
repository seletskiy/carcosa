package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/docopt/docopt-go"
	"github.com/seletskiy/hierr"
)

var globalMasterKey []byte

const tokenHashDelimiter = "::"

const usage = `carcosa - git-backed secrets storage.

Tool provides a way of storing arbitrary data inside encrypted git objects.

Encryption is done via AES cypher.

Each encrypted data object can be referenced via non-unique name, which is
called token. Tokens are encrypted as well.

Encrypted data objects are linked to git refs.

First, you need to initialize git repo or use existing repo.
However, if you already have git repo, you can use '-S' to obtain data from
that repo:

  carcosa -Sr git://path.to/repo.git

Then, use '-A' for adding new secret:

  carcosa -A my-new-secret

Secrets will be listed by using '-L':

  carcosa -L

Stored secret can be obtained via '-G':

  carcosa -G my-new-secret

Note, that same master password should be used. You can use different master
passwords for different secrets.

Remote sync is controlled via '-n' and '-y' flags, see more in usage.

Usage:
    carcosa [options] -h | --help
    carcosa [options] -S [-c] [-n] [-r <remote>]
    carcosa [options] -A [-c] [-n] <token>
    carcosa [options] -M [-c] [-n] <token>
    carcosa [options] -G [-c] [-y] <token>
    carcosa [options] -L [-c] [-y]
    carcosa [options] -R [-c] [-n] <token>
    carcosa [options] -F -c

Options:
    -h --help      Show this help.
    -S --sync      Initializes local storage from the remote or sync with
                    already initialized storage (push & pull).  Push can be
                    prohibited by using '-n' flag.
                    If target directory is empty, then remote will be cloned
                    and therefore should be specified via '-r' flag.
    -A --add       Add secret for specified token. Secret will be read from
                    stdin.
    -M --modify    Modify secret for specified token in place. '-e' flag can be
                    used to set editor.
    -G --get       Get secret by specified token.
    -L --list      List tokens.
    -R --remove    Remove secret by specified token.
    -F --keycheck  Check that master password cache presents and exit if it is
                    not. Suitable for scripting purposes.
    -s <ref-ns>    Use specified ref namespace.
                    [default: refs/tokens/]
    -p <path>      Set git repo path to store secrets in.
                    [default: .]
    -n             Do not interact with remote repo (no push / no pull).
    -y             Sync with remote before doing anything else.
    -r <remote>    Remote repository name to use.
                    [default: origin].
    -c             Use cache for master password. Master password will be
                    encrypted using unique encryption key for current machine.
    -f <cache>     Cache file prefix for master password. Acutal file name will
                    ends with hash suffix.
                    [default: ~/.config/carcosa/master]
    -k <file>      Read master key from specified file. WARNING: that can be
                    unsecure; use of fifo pipe as a file is preferable.
    -e <editor>    Use specified editor for modifying secret in place.
                    [default: $EDITOR]
`

func main() {
	usage := strings.Replace(usage, "~/", os.Getenv("HOME")+"/", -1)
	usage = strings.Replace(usage, "$EDITOR", os.Getenv("EDITOR"), -1)

	args, err := docopt.Parse(usage, nil, true, "1", false)
	if err != nil {
		panic(err)
	}

	switch {
	case args["--sync"].(bool):
		err = syncSecrets(args)
	case args["--add"].(bool):
		err = addSecret(args)
	case args["--get"].(bool):
		err = getSecret(args)
	case args["--list"].(bool):
		err = listSecrets(args)
	case args["--modify"].(bool):
		err = modifySecret(args)
	case args["--remove"].(bool):
		err = removeSecret(args)
	case args["--keycheck"].(bool):
		err = checkMasterPasswordCache(args)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func addSecret(args map[string]interface{}) error {
	var (
		token        = []byte(args["<token>"].(string))
		refNamespace = args["-s"].(string)
		repoPath     = args["-p"].(string)
		remote       = args["-r"].(string)
		doSync       = !args["-n"].(bool)
	)

	masterKey, err := readMasterKey(args)
	if err != nil {
		return hierr.Errorf(err, "can't read master key")
	}

	plaintext, err := readPlainText()
	if err != nil {
		return hierr.Errorf(err, "can't read plaintext")
	}

	repo := git{
		path: repoPath,
	}

	encryptedToken, ciphertext, err := encryptBlob(token, plaintext, masterKey)
	if err != nil {
		return hierr.Errorf(err, "can't encrypt blob")
	}

	hash, err := repo.writeObject(ciphertext.getBody())
	if err != nil {
		return hierr.Errorf(err, "can't write Git object with ciphertext")
	}

	err = repo.updateRef(
		filepath.Join(refNamespace, hex.EncodeToString(encryptedToken)), hash,
	)
	if err != nil {
		return hierr.Errorf(err, "can't set ref for Git object '%s'", hash)
	}

	if doSync {
		err := pushRemote(repo, remote, refNamespace)
		if err != nil {
			return hierr.Errorf(err, "can't sync with remote")
		}
	}

	return nil
}

func modifySecret(args map[string]interface{}) error {
	var (
		editor = args["-e"].(string)
		noPush = args["-n"].(bool)
	)

	secret, err := extractSecret(args)
	if err != nil {
		return err
	}

	plaintext := []byte{}
	if secret != nil {
		plaintext, err = ioutil.ReadAll(secret.stream)
		if err != nil {
			return hierr.Errorf(
				err,
				"can't obtain plaintext from secret",
			)
		}
	}

	os.Stdin, err = openEditor(editor, plaintext)
	if err != nil {
		return hierr.Errorf(err, "can't edit secret's text")
	}

	args["-n"] = true
	err = addSecret(args)
	if err != nil {
		if _, ok := err.(remoteError); ok {
			log.Println(err)
		} else {
			return hierr.Errorf(
				err,
				"can't add modified secret",
			)
		}
	}

	if secret != nil {
		args["<token>"] = secret.token + tokenHashDelimiter + secret.hash
		args["-n"] = noPush
		err = removeSecret(args)
		if err != nil {
			return hierr.Errorf(
				err,
				"can't remove old secret",
			)
		}
	}

	return nil
}

func openEditor(editor string, plaintext []byte) (*os.File, error) {
	buffer, err := ioutil.TempFile(os.TempDir(), "carcosa")
	if err != nil {
		return nil, hierr.Errorf(
			err,
			"can't create temporary buffer file '%s'",
			buffer.Name(),
		)
	}

	err = buffer.Chmod(0600)
	if err != nil {
		return nil, hierr.Errorf(
			err,
			"can't chmod 0600 temporary buffer file '%s'",
			buffer.Name(),
		)
	}

	_, err = buffer.Write(plaintext)
	if err != nil {
		return nil, hierr.Errorf(
			err,
			"can't write data to temporary buffer file '%s'",
			buffer.Name(),
		)
	}

	err = buffer.Sync()
	if err != nil {
		return nil, hierr.Errorf(
			err,
			"can't sync data to temporary buffer file '%s'",
			buffer.Name(),
		)
	}

	cmd := exec.Command(editor, buffer.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		return nil, hierr.Errorf(
			err,
			"editor '%s %s' exited with error", editor, buffer.Name(),
		)
	}

	_, err = buffer.Seek(0, 0)
	if err != nil {
		return nil, hierr.Errorf(
			err,
			"can't seek to the beginning of the file '%s'",
			buffer.Name(),
		)
	}

	return buffer, nil

}

func extractSecret(args map[string]interface{}) (*secret, error) {
	var (
		token        = args["<token>"].(string)
		refNamespace = args["-s"].(string)
		repoPath     = args["-p"].(string)
		syncFirst    = args["-y"].(bool)
		remote       = args["-r"].(string)
	)

	repo := git{
		path: repoPath,
	}

	if syncFirst {
		err := fetchRemote(repo, remote, refNamespace)
		if err != nil {
			return nil, hierr.Errorf(
				err,
				"can't sync with remote",
			)
		}
	}

	masterKey, err := readMasterKey(args)
	if err != nil {
		return nil, hierr.Errorf(err, "can't read master key")
	}

	secrets, err := getSecretsFromRepo(repo, refNamespace, masterKey)
	if err != nil {
		return nil, hierr.Errorf(
			err,
			"can't get secrets from repo '%s'", repoPath,
		)
	}

	tokenHash := ""
	hashDelimIndex := strings.LastIndex(token, tokenHashDelimiter)
	if hashDelimIndex > 0 {
		tokenHash = token[hashDelimIndex+2:]
		token = token[:hashDelimIndex]
	}

	for _, secret := range secrets {
		if secret.token != token {
			continue
		}

		if tokenHash != "" && !strings.HasPrefix(secret.hash, tokenHash) {
			continue
		}

		return &secret, nil
	}

	return nil, nil
}

func getSecret(args map[string]interface{}) error {
	var (
		token    = args["<token>"].(string)
		repoPath = args["-p"].(string)
	)

	secret, err := extractSecret(args)
	if err != nil {
		return err
	}

	if secret == nil {
		return fmt.Errorf(
			"no secret with token '%s' found in the repo '%s'",
			token, repoPath,
		)
	}

	plaintext, err := ioutil.ReadAll(secret.stream)
	if err != nil {
		return hierr.Errorf(
			err,
			"can't obtain plaintext from secret",
		)
	}

	fmt.Print(string(plaintext))

	return nil
}

func listSecrets(args map[string]interface{}) error {
	var (
		refNamespace = args["-s"].(string)
		repoPath     = args["-p"].(string)
		syncFirst    = args["-y"].(bool)
	)

	if syncFirst {
		err := syncSecrets(args)
		if err != nil {
			return hierr.Errorf(
				err,
				"can't sync with remote",
			)
		}
	}

	masterKey, err := readMasterKey(args)
	if err != nil {
		return hierr.Errorf(err, "can't read master key")
	}

	repo := git{
		path: repoPath,
	}

	secrets, err := getSecretsFromRepo(repo, refNamespace, masterKey)
	if err != nil {
		return hierr.Errorf(
			err,
			"can't get secrets from repo '%s'", repoPath,
		)
	}

	listed := map[string]struct{}{}
	for _, secret := range secrets {
		if _, ok := listed[secret.token]; ok {
			fmt.Println(secret.token + tokenHashDelimiter + secret.hash[:7])
		} else {
			fmt.Println(secret.token)
		}
		listed[secret.token] = struct{}{}
	}

	return nil
}

func removeSecret(args map[string]interface{}) error {
	var (
		token        = args["<token>"].(string)
		repoPath     = args["-p"].(string)
		refNamespace = args["-s"].(string)
		remote       = args["-r"].(string)
		doPush       = !args["-n"].(bool)
	)

	secret, err := extractSecret(args)
	if err != nil {
		return err
	}

	if secret == nil {
		return fmt.Errorf(
			"no secret with token '%s' found in the repo '%s'",
			token, repoPath,
		)
	}

	repo := git{
		path: repoPath,
	}

	err = repo.removeRef(secret.ref.name)
	if err != nil {
		return hierr.Errorf(
			err,
			"can't remove ref '%s'", secret.ref.name,
		)
	}

	if doPush {
		err := pushRemote(repo, remote, refNamespace)
		if err != nil {
			return err
		}
	}

	return nil
}

func syncSecrets(args map[string]interface{}) error {
	var (
		refNamespace = args["-s"].(string)
		repoPath     = args["-p"].(string)
		remote       = args["-r"].(string)
		doPush       = !args["-n"].(bool)
	)

	repo := git{
		path: repoPath,
	}

	if doPush {
		err := pushRemote(repo, remote, refNamespace)
		if err != nil {
			return err
		}
	}

	err := fetchRemote(repo, remote, refNamespace)
	if err != nil {
		return err
	}

	return nil
}

func checkMasterPasswordCache(args map[string]interface{}) error {
	args["-k"] = "/dev/null"

	_, err := readMasterKey(args)
	if err != nil {
		return hierr.Errorf(err, "can't read master key")
	}

	return nil
}

func readMasterKey(args map[string]interface{}) ([]byte, error) {
	var (
		useCache             = args["-c"].(bool)
		cacheFileName        = args["-f"].(string)
		masterKeyFileName, _ = args["-k"].(string)
	)

	if len(globalMasterKey) > 0 {
		return globalMasterKey, nil
	}

	if useCache {
		masterKey, err := getMasterKeyFromCache(cacheFileName)
		if err != nil {
			return nil, hierr.Errorf(
				err,
				"can't retrieve master key from cache",
			)
		}

		if masterKey != nil {
			return masterKey, nil
		}
	}

	if stat, err := os.Stdin.Stat(); err != nil {
		return nil, hierr.Errorf(err, "can't stat stdin")
	} else {
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			return nil, hierr.Errorf(
				err, "interactive terminal required, pipe given",
			)
		}
	}

	var masterKey []byte
	var err error

	if masterKeyFileName == "" {
		fmt.Fprint(os.Stderr, "Enter master password: ")
		masterKey, err = terminal.ReadPassword(0)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, hierr.Errorf(
				err, "can't read master password from terminal",
			)
		}
	} else {
		masterKey, err = ioutil.ReadFile(masterKeyFileName)
		if err != nil {
			return nil, hierr.Errorf(
				err, "can't read master password from file",
			)
		}
	}

	if len(masterKey) < 1 {
		return nil, fmt.Errorf("master key can't be empty")
	}

	paddedMasterKey, err := padBytesToBlockKey(masterKey)
	if err != nil {
		return nil, err
	}

	if useCache {
		err := storeMasterKeyCache(paddedMasterKey, cacheFileName)
		if err != nil {
			return nil, hierr.Errorf(
				err,
				"can't store master key cache",
			)
		}
	}

	globalMasterKey = paddedMasterKey

	return paddedMasterKey, nil
}

func readPlainText() ([]byte, error) {
	plaintext, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return nil, hierr.Errorf(err, "can't read secret body")
	}

	return plaintext, nil
}

func getSecretsFromRepo(
	repo git, refNamespace string, masterKey []byte,
) ([]secret, error) {
	encryptedTokens, err := repo.listRefs(refNamespace)
	if err != nil {
		return nil, hierr.Errorf(err, "can't get tokens")
	}

	secrets := []secret{}

	for _, ref := range encryptedTokens {
		hexToken := strings.TrimPrefix(ref.name, refNamespace)
		blobBody, err := repo.catFile(ref.hash)
		if err != nil {
			return nil, hierr.Errorf(
				err,
				"can't get ciphertext from",
			)
		}

		encryptedToken, err := hex.DecodeString(hexToken)
		if err != nil {
			return nil, hierr.Errorf(
				err,
				"can't decode hex token '%s'", hexToken,
			)
		}

		secret, err := decryptBlob(encryptedToken, blobBody, masterKey)
		if err != nil {
			if err != errInvalidHMAC {
				return nil, hierr.Errorf(
					err,
					"can't decrypt blob for token '%s'", hexToken,
				)
			}
		} else {
			secret.ref = ref
			secrets = append(secrets, *secret)
		}
	}

	return secrets, nil
}

func storeMasterKeyCache(masterKey []byte, cacheFileName string) error {
	machineKey, err := getUniqueMachineID()
	if err != nil {
		return hierr.Errorf(err, "can't obtain machine key")
	}

	encryptedToken, ciphertext, err := encryptBlob(
		[]byte(filepath.Base(cacheFileName)), masterKey, machineKey,
	)

	targetCacheName := filepath.Join(
		filepath.Dir(cacheFileName),
		filepath.Base(cacheFileName)+"."+hex.EncodeToString(encryptedToken),
	)

	err = os.MkdirAll(filepath.Dir(targetCacheName), 0700)
	if err != nil {
		return hierr.Errorf(
			err,
			"can't create dir for '%s'", targetCacheName,
		)
	}

	file, err := os.OpenFile(
		targetCacheName, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600,
	)
	if err != nil {
		return hierr.Errorf(
			err,
			"can't create cache file '%s' for master key",
			targetCacheName,
		)
	}

	_, err = file.Write(ciphertext.getBody())
	if err != nil {
		return hierr.Errorf(
			err,
			"can't write encrypted master key to '%s'",
			targetCacheName,
		)
	}

	err = file.Close()
	if err != nil {
		return hierr.Errorf(
			err,
			"can't close cache file '%s'", targetCacheName,
		)
	}

	return nil
}

func getMasterKeyFromCache(cacheFileName string) ([]byte, error) {
	machineKey, err := getUniqueMachineID()
	if err != nil {
		return nil, hierr.Errorf(err, "can't obtain machine key")
	}

	candidates, err := filepath.Glob(cacheFileName + ".*")
	if err != nil {
		return nil, hierr.Errorf(
			err,
			"can't glob for '%s.*'", cacheFileName,
		)
	}

	for _, candidate := range candidates {
		hexToken := strings.TrimPrefix(candidate, cacheFileName+".")
		encryptedKey, err := ioutil.ReadFile(candidate)
		if err != nil {
			return nil, hierr.Errorf(
				err,
				"can't read encrypted master key from '%s'",
				candidate,
			)
		}

		encryptedToken, err := hex.DecodeString(hexToken)
		if err != nil {
			return nil, hierr.Errorf(
				err,
				"can't decode hex token '%s'", hexToken,
			)
		}

		secret, err := decryptBlob(encryptedToken, encryptedKey, machineKey)
		if err != nil {
			if err != errInvalidHMAC {
				return nil, hierr.Errorf(
					err,
					"can't decrypt master key from '%s'",
					candidate,
				)
			}
		}

		masterKey, err := ioutil.ReadAll(secret.stream)
		if err != nil {
			return nil, hierr.Errorf(
				err,
				"can't decrypt master key stream from '%s'",
				candidate,
			)
		}

		if len(masterKey) < 1 {
			return nil, fmt.Errorf(
				"empty key specified in '%s'",
				candidate,
			)
		}

		return masterKey, nil
	}

	return nil, nil
}

func getUniqueMachineID() ([]byte, error) {
	hash := sha256.New()

	err := filepath.Walk(
		"/dev/disk/by-uuid",
		func(path string, info os.FileInfo, err error) error {
			_, err = hash.Write([]byte(path))
			if err != nil {
				return hierr.Errorf(err, "error hashing path '%s'", path)
			}

			return nil
		},
	)

	if err != nil {
		return nil, hierr.Errorf(
			err,
			"can't list machine disks from /dev/disk",
		)
	}

	return hash.Sum(nil), nil
}
