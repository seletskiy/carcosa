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
)

var globalMasterKey []byte

const tokenHashDelimiter = "::"

const usage = `$0 - git-backed secrets storage.

<TBD>

Usage:
    $0 [options] -h | --help
    $0 [options] -S [-n] [-r <remote>]
    $0 [options] -A [-n] <token>
    $0 [options] -M [-n] <token>
    $0 [options] -G [-y] <token>
    $0 [options] -L [-y]
    $0 [options] -R [-n] <token>

Options:
    -h --help    Show this help.
    -S --sync    Initializes local storage from the remote or sync with already
                   initialized storage (push & pull).
                   Push can be prohibited by using '-n' flag.
                   If target directory is empty, then remote will be cloned and
                   therefore should be specified via '-r' flag.
    -A --add     Add secret for specified token. Secret will be read from
    -M --modify  Modify secret for specified token in place. '-e' flag can be
                   used to set editor.
    -G --get     Get secret by specified token.
    -L --list    List tokens.
    -R --remove  Remove secret by specified token.
    -s <ref-ns>  Use specified ref namespace.
                   [default: refs/tokens/]
    -p <path>    Set git repo path to store secrets in.
                   [default: .]
    -n           Do not interact with remote repo (no push / no pull).
    -y           Sync with remote before doing anything else.
    -r <remote>  Remote repository name to use.
                   [default: origin].
    -c           Use cache for master password. Master password will be
                   encrypted using unique encryption key for current machine.
    -f <cache>   Cache file for master password.
                   [default: ~/.config/carcossa/master]
    -e <editor>  Use specified editor for modifying secret in place.
                   [default: $EDITOR]
`

func main() {
	usage := strings.Replace(usage, "$0", os.Args[0], -1)
	usage = strings.Replace(usage, "~/", os.Getenv("HOME")+"/", -1)
	usage = strings.Replace(usage, "$EDITOR", os.Getenv("EDITOR"), -1)

	args, err := docopt.Parse(usage, nil, true, "1.0", false)
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
		return fmt.Errorf("can't read master key: %s", err)
	}

	plaintext, err := readPlainText()
	if err != nil {
		return fmt.Errorf("can't read plaintext: %s", err)
	}

	repo := git{
		path: repoPath,
	}

	encryptedToken, ciphertext, err := encryptBlob(token, plaintext, masterKey)
	if err != nil {
		return fmt.Errorf("can't encrypt blob: %s", err)
	}

	hash, err := repo.writeObject(ciphertext.getBody())
	if err != nil {
		return fmt.Errorf("can't write Git object with ciphertext: %s", err)
	}

	err = repo.updateRef(
		filepath.Join(refNamespace, hex.EncodeToString(encryptedToken)), hash,
	)
	if err != nil {
		return fmt.Errorf("can't set ref for Git object '%s': %s", hash, err)
	}

	if doSync {
		err := pushRemote(repo, remote, refNamespace)
		if err != nil {
			return fmt.Errorf("can't sync with remote: %s", err)
		}
	}

	return nil
}

func modifySecret(args map[string]interface{}) error {
	var (
		editor = args["-e"].(string)
		doPush = !args["-n"].(bool)
	)

	secret, err := extractSecret(args)
	if err != nil {
		return err
	}

	plaintext := []byte{}
	if secret != nil {
		plaintext, err = ioutil.ReadAll(secret.stream)
		if err != nil {
			return fmt.Errorf(
				"can't obtain plaintext from secret: %s", err,
			)
		}
	}

	os.Stdin, err = openEditor(editor, plaintext)
	if err != nil {
		return fmt.Errorf("can't edit secret's text: %s", err)
	}

	args["-n"] = true
	err = addSecret(args)
	if err != nil {
		if _, ok := err.(remoteError); ok {
			log.Println(err)
		} else {
			return fmt.Errorf(
				"can't add modified secret: %s", err,
			)
		}
	}

	if secret != nil {
		args["<token>"] = secret.token + tokenHashDelimiter + secret.hash
		args["-n"] = !doPush
		err = removeSecret(args)
		if err != nil {
			return fmt.Errorf(
				"can't remove old secret: %s", err,
			)
		}
	}

	return nil
}

func openEditor(editor string, plaintext []byte) (*os.File, error) {
	buffer, err := ioutil.TempFile(os.TempDir(), "carcossa")
	buffer.Chmod(0600)
	_, err = buffer.Write(plaintext)
	if err != nil {
		return nil, fmt.Errorf(
			"can't write data to temporary buffer file '%s': %s",
			buffer.Name(), err,
		)
	}

	err = buffer.Sync()
	if err != nil {
		return nil, fmt.Errorf(
			"can't sync data to temporary buffer file '%s': %s",
			buffer.Name(), err,
		)
	}

	cmd := exec.Command(editor, buffer.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Env = append(os.Environ(), []string{"CARCOSSA_MASTER_KEY="}...)

	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf(
			"editor '%s %s' exited with error: %s", editor, buffer.Name(), err,
		)
	}

	_, err = buffer.Seek(0, 0)
	if err != nil {
		return nil, fmt.Errorf(
			"can't seek to the beginning of the file '%s': %s",
			buffer.Name(), err,
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
			return nil, fmt.Errorf(
				"can't sync with remote: %s", err,
			)
		}
	}

	masterKey, err := readMasterKey(args)
	if err != nil {
		return nil, fmt.Errorf("can't read master key: %s", err)
	}

	secrets, err := getSecretsFromRepo(repo, refNamespace, masterKey)
	if err != nil {
		return nil, fmt.Errorf(
			"can't get secrets from repo '%s': %s", repoPath, err,
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
		return fmt.Errorf(
			"can't obtain plaintext from secret: %s", err,
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
			return fmt.Errorf(
				"can't sync with remote: %s", err,
			)
		}
	}

	masterKey, err := readMasterKey(args)
	if err != nil {
		return fmt.Errorf("can't read master key: %s", err)
	}

	repo := git{
		path: repoPath,
	}

	secrets, err := getSecretsFromRepo(repo, refNamespace, masterKey)
	if err != nil {
		return fmt.Errorf(
			"can't get secrets from repo '%s': %s", repoPath, err,
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
		return fmt.Errorf(
			"can't remove ref '%s': %s", secret.ref.name, err,
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

func readMasterKey(args map[string]interface{}) ([]byte, error) {
	var (
		useCache      = args["-c"].(bool)
		cacheFileName = args["-f"].(string)
	)

	if os.Getenv("CARCOSSA_MASTER_KEY") != "" {
		masterKey, err := hex.DecodeString(os.Getenv("CARCOSSA_MASTER_KEY"))
		if err != nil {
			return nil, fmt.Errorf(
				"can't decode hex value of CARCOSSA_MASTER_KEY env var: %s",
				err,
			)
		}

		return []byte(masterKey), nil
	}

	if useCache {
		masterKey, err := getMasterKeyFromCache(cacheFileName)
		if err != nil {
			return nil, fmt.Errorf(
				"can't retrieve master key from cache: %s", err,
			)
		}

		if masterKey != nil {
			return masterKey, nil
		}
	}

	fmt.Fprint(os.Stderr, "Enter master password: ")
	masterKey, err := terminal.ReadPassword(0)
	if err != nil {
		return nil, fmt.Errorf("can't read master password: %s", err)
	}

	fmt.Fprint(os.Stderr, "\n")

	if useCache {
		err := storeMasterKeyCache(masterKey, cacheFileName)
		if err != nil {
			return nil, fmt.Errorf(
				"can't store master key cache: %s", err,
			)
		}
	}

	paddedMasterKey, err := padBytesToBlockKey(masterKey)
	if err != nil {
		return nil, err
	}

	err = os.Setenv("CARCOSSA_MASTER_KEY", hex.EncodeToString(paddedMasterKey))

	return paddedMasterKey, nil
}

func readPlainText() ([]byte, error) {
	plaintext, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("can't read secret body: %s", err)
	}

	return plaintext, nil
}

func getSecretsFromRepo(
	repo git, refNamespace string, masterKey []byte,
) ([]secret, error) {
	encryptedTokens, err := repo.listRefs(refNamespace)
	if err != nil {
		return nil, fmt.Errorf("can't get tokens: %s", err)
	}

	secrets := []secret{}

	for _, ref := range encryptedTokens {
		hexToken := strings.TrimPrefix(ref.name, refNamespace)
		blobBody, err := repo.catFile(ref.hash)
		if err != nil {
			return nil, fmt.Errorf(
				"can't get ciphertext from: %s", err,
			)
		}

		encryptedToken, err := hex.DecodeString(hexToken)
		if err != nil {
			return nil, fmt.Errorf(
				"can't decode hex token '%s': %s", hexToken, err,
			)
		}

		secret, err := decryptBlob(encryptedToken, blobBody, masterKey)
		if err != nil {
			if err != errInvalidHMAC {
				return nil, fmt.Errorf(
					"can't decrypt blob for token '%s': %s", hexToken, err,
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
		return fmt.Errorf("can't obtain machine key: %s", err)
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
		return fmt.Errorf(
			"can't create dir for '%s': %s", targetCacheName, err,
		)
	}

	file, err := os.OpenFile(
		targetCacheName, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600,
	)
	if err != nil {
		return fmt.Errorf(
			"can't create cache file '%s' for master key: %s",
			targetCacheName, err,
		)
	}

	_, err = file.Write(ciphertext.getBody())
	if err != nil {
		return fmt.Errorf(
			"can't write encrypted master key to '%s': %s",
			targetCacheName, err,
		)
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf(
			"can't close cache file '%s': %s", targetCacheName, err,
		)
	}

	return nil
}

func getMasterKeyFromCache(cacheFileName string) ([]byte, error) {
	machineKey, err := getUniqueMachineID()
	if err != nil {
		return nil, fmt.Errorf("can't obtain machine key: %s", err)
	}

	candidates, err := filepath.Glob(cacheFileName + ".*")
	if err != nil {
		return nil, fmt.Errorf(
			"can't glob for '%s.*': %s", cacheFileName, err,
		)
	}

	for _, candidate := range candidates {
		hexToken := strings.TrimPrefix(candidate, cacheFileName+".")
		encryptedKey, err := ioutil.ReadFile(candidate)
		if err != nil {
			return nil, fmt.Errorf(
				"can't read encrypted master key from '%s': %s",
				candidate, err,
			)
		}

		encryptedToken, err := hex.DecodeString(hexToken)
		if err != nil {
			return nil, fmt.Errorf(
				"can't decode hex token '%s': %s", hexToken, err,
			)
		}

		secret, err := decryptBlob(encryptedToken, encryptedKey, machineKey)
		if err != nil {
			if err != errInvalidHMAC {
				return nil, fmt.Errorf(
					"can't decrypt master key from '%s': %s",
					candidate, err,
				)
			}
		}

		masterKey, err := ioutil.ReadAll(secret.stream)
		if err != nil {
			return nil, fmt.Errorf(
				"can't decrypt master key stream from '%s': %s",
				candidate, err,
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
				return fmt.Errorf("error hashing path '%s': %s", path, err)
			}

			return nil
		},
	)

	if err != nil {
		return nil, fmt.Errorf(
			"can't list machine disks from /dev/disk: %s", err,
		)
	}

	return hash.Sum(nil), nil
}
