package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/docopt/docopt-go"
	"github.com/kovetskiy/lorg"
	"github.com/reconquest/karma-go"
)

var globalMasterKey []byte

var usage = `carcosa - git-backed secrets storage.

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
    carcosa [options] [-v]... -h | --help | --version
    carcosa [options] [-v]... -S [-c] [-n] [-r <remote>]
    carcosa [options] [-v]... -A [-c] [-n] <token>
    carcosa [options] [-v]... -M [-c] [-n] <token>
    carcosa [options] [-v]... -G [-c] [-y] <token>
    carcosa [options] [-v]... -L [-c] [-y]
    carcosa [options] [-v]... -R [-c] [-n] <token>
    carcosa [options] [-v]... -F -c

Options:
    -h --help      Show this help.
    -S --sync      Initializes local storage from the remote or sync with
                    already initialized storage (pull & push).  Push can be
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
                    [default: $SECRETS_PATH]
    -n             Do not interact with remote repo (no push / no pull).
    -y             Sync with remote before doing anything else.
    -r <remote>    Remote repository name to use.
                    [default: origin].
    -c             Use cache for master password. Master password will be
                    encrypted using unique encryption key for current machine.
    -f <cache>     Cache file prefix for master password. Actual file name will
                    ends with hash suffix.
                    [default: $CACHE_PATH]
    -k <file>      Read master key from specified file. WARNING: that can be
                    unsecure; use of fifo pipe as a file is preferable.
    -e <editor>    Use specified editor for modifying secret in place.
                    [default: $EDITOR]
    -v             Verbose output.
`

type Opts struct {
	ArgToken             string `docopt:"<token>"`
	ModeSync             bool   `docopt:"--sync"`
	ModeAdd              bool   `docopt:"--add"`
	ModeModify           bool   `docopt:"--modify"`
	ModeGet              bool   `docopt:"--get"`
	ModeList             bool   `docopt:"--list"`
	ModeRemove           bool   `docopt:"--remove"`
	ModeKeycheck         bool   `docopt:"--keycheck"`
	ValueNamespace       string `docopt:"-s"`
	ValuePath            string `docopt:"-p"`
	ValueRemote          string `docopt:"-r"`
	ValueMasterCachePath string `docopt:"-f"`
	ValueMasterFile      string `docopt:"-k"`
	ValueEditor          string `docopt:"-e"`
	FlagNoSync           bool   `docopt:"-n"`
	FlagSyncFirst        bool   `docopt:"-y"`
	FlagUseMasterCache   bool   `docopt:"-c"`
	FlagVerbose          int    `docopt:"-v"`
}

func init() {
	human, err := user.Current()
	if err != nil {
		panic(err)
	}

	home := human.HomeDir

	usage = strings.NewReplacer(
		"$EDITOR",
		/* -> */ os.Getenv("EDITOR"),
		"$SECRETS_PATH",
		/* -> */ filepath.Join(home, ".secrets"),
		"$CACHE_PATH",
		/* -> */ filepath.Join(home, ".config", "carcosa", "master"),
	).Replace(usage)
}

func main() {
	args, err := docopt.ParseArgs(usage, nil, "2")
	if err != nil {
		panic(err)
	}

	var opts Opts

	err = args.Bind(&opts)
	if err != nil {
		log.Fatal(err)
	}

	switch opts.FlagVerbose {
	case 0:
		log.SetLevel(lorg.LevelInfo)
	case 1:
		log.SetLevel(lorg.LevelDebug)
	default:
		log.SetLevel(lorg.LevelTrace)
	}

	switch {
	case opts.ModeSync:
		err = syncSecrets(opts)
	case opts.ModeAdd:
		err = addSecret(opts)
	case opts.ModeGet:
		err = getSecret(opts)
	case opts.ModeList:
		err = listSecrets(opts)
	case opts.ModeModify:
		err = modifySecret(opts)
	case opts.ModeRemove:
		err = removeSecret(opts)
	case opts.ModeKeycheck:
		err = checkMasterPasswordCache(opts)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func addSecret(opts Opts) error {
	var (
		token    = opts.ArgToken
		ns       = opts.ValueNamespace
		repoPath = opts.ValuePath
		remote   = opts.ValueRemote
		doSync   = !opts.FlagNoSync
	)

	masterKey, err := readMasterKey(opts)
	if err != nil {
		return karma.Format(err, "unable to read master key")
	}

	repo, err := open(repoPath)
	if err != nil {
		return err
	}

	secrets, err := getSecretsFromRepo(repo, ns, masterKey)
	if err != nil {
		return karma.Format(
			err,
			"unable to get secrets from repo %q", repoPath,
		)
	}

	for _, secret := range secrets {
		if secret.token == token {
			return fmt.Errorf(
				"secret with name %q already exists",
				token,
			)
		}
	}

	plaintext, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return karma.Format(err, "unable to read secret body")
	}

	encryptedToken, ciphertext, err := encryptBlob(
		[]byte(token),
		plaintext,
		masterKey,
	)
	if err != nil {
		return karma.Format(err, "unable to encrypt blob")
	}

	hash, err := repo.write(ciphertext.getBody())
	if err != nil {
		return karma.Format(err, "unable to write git object with ciphertext")
	}

	ref := ref{
		name: filepath.Join(ns, hex.EncodeToString(encryptedToken)),
		hash: hash,
	}

	err = repo.update(ref)
	if err != nil {
		return karma.Format(err, "unable to set ref for git object %q", hash)
	}

	err = repo.update(ref.as(addition))
	if err != nil {
		return karma.Format(err, "unable to mark ref %q as added", ref.name)
	}

	if doSync {
		err := sync(repo, remote, ns)
		if err != nil {
			return karma.Format(err, "unable to sync with remote")
		}
	}

	return nil
}

func modifySecret(opts Opts) error {
	var (
		editor = opts.ValueEditor
		noSync = opts.FlagNoSync
	)

	secret, err := extractSecret(opts)
	if err != nil {
		return err
	}

	plaintext, err := ioutil.ReadAll(secret.stream)
	if err != nil {
		return karma.Format(err, "unable to obtain plaintext from secret")
	}

	os.Stdin, err = openEditor(editor, plaintext)
	if err != nil {
		return karma.Format(err, "unable to edit secret's text")
	}

	defer func() { os.Remove(os.Stdin.Name()) }()

	opts.FlagNoSync = true
	err = removeSecret(opts)
	if err != nil {
		return karma.Format(err, "unable to remove old secret")
	}

	opts.FlagNoSync = noSync
	err = addSecret(opts)
	if err != nil {
		return karma.Format(err, "unable to add modified secret")
	}

	return nil
}

func openEditor(editor string, plaintext []byte) (*os.File, error) {
	buffer, err := ioutil.TempFile(os.TempDir(), "carcosa.secret.")
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to create temporary buffer file %q",
			buffer.Name(),
		)
	}

	err = buffer.Chmod(0600)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to chmod 0600 temporary buffer file %q",
			buffer.Name(),
		)
	}

	_, err = buffer.Write(plaintext)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to write data to temporary buffer file %q",
			buffer.Name(),
		)
	}

	err = buffer.Sync()
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to sync data to temporary buffer file %q",
			buffer.Name(),
		)
	}

	cmd := exec.Command(editor, buffer.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		return nil, karma.Format(
			err,
			"editor '%s %s' exited with error", editor, buffer.Name(),
		)
	}

	_, err = buffer.Seek(0, 0)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to seek to the beginning of the file %q",
			buffer.Name(),
		)
	}

	return buffer, nil

}

func extractSecret(opts Opts) (*secret, error) {
	var (
		token     = opts.ArgToken
		ns        = opts.ValueNamespace
		repoPath  = opts.ValuePath
		syncFirst = opts.FlagSyncFirst
		remote    = opts.ValueRemote
	)

	repo, err := open(repoPath)
	if err != nil {
		return nil, err
	}

	if syncFirst {
		err := sync(repo, remote, ns)
		if err != nil {
			return nil, karma.Format(
				err,
				"unable to sync with remote",
			)
		}
	}

	masterKey, err := readMasterKey(opts)
	if err != nil {
		return nil, karma.Format(err, "unable to read master key")
	}

	secrets, err := getSecretsFromRepo(repo, ns, masterKey)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to get secrets from repo %q", repoPath,
		)
	}

	for _, secret := range secrets {
		if secret.token != token {
			continue
		}

		return &secret, nil
	}

	return nil, fmt.Errorf(
		"no secret with token %q found",
		token,
	)
}

func getSecret(opts Opts) error {
	secret, err := extractSecret(opts)
	if err != nil {
		return err
	}

	plaintext, err := ioutil.ReadAll(secret.stream)
	if err != nil {
		return karma.Format(
			err,
			"unable to obtain plaintext from secret",
		)
	}

	fmt.Print(string(plaintext))

	return nil
}

func listSecrets(opts Opts) error {
	var (
		ns        = opts.ValueNamespace
		repoPath  = opts.ValuePath
		syncFirst = opts.FlagSyncFirst
	)

	if syncFirst {
		err := syncSecrets(opts)
		if err != nil {
			return karma.Format(
				err,
				"unable to sync with remote",
			)
		}
	}

	masterKey, err := readMasterKey(opts)
	if err != nil {
		return karma.Format(err, "unable to read master key")
	}

	repo, err := open(repoPath)
	if err != nil {
		return err
	}

	secrets, err := getSecretsFromRepo(repo, ns, masterKey)
	if err != nil {
		return karma.Format(
			err,
			"unable to get secrets from repo %q", repoPath,
		)
	}

	for _, secret := range secrets {
		log.Tracef("[hash] %s", secret.ref.hash)
		log.Tracef("[ref]  %s", secret.ref.name)
		fmt.Println(secret.token)
	}

	return nil
}

func removeSecret(opts Opts) error {
	var (
		token    = opts.ArgToken
		repoPath = opts.ValuePath
		ns       = opts.ValueNamespace
		remote   = opts.ValueRemote
		doSync   = !opts.FlagNoSync
	)

	secret, err := extractSecret(opts)
	if err != nil {
		return err
	}

	if secret == nil {
		return fmt.Errorf(
			"no secret with token %q found in the repo %q",
			token, repoPath,
		)
	}

	repo, err := open(repoPath)
	if err != nil {
		return err
	}

	err = repo.delete(secret.ref)
	if err != nil {
		return karma.Format(
			err,
			"unable to remove ref %q", secret.ref.name,
		)
	}

	err = repo.update(secret.ref.as(deletion))
	if err != nil {
		return karma.Format(
			err,
			"unable to mark ref %q as deleted", secret.ref.name,
		)
	}

	if doSync {
		err := sync(repo, remote, ns)
		if err != nil {
			return err
		}
	}

	return nil
}

func syncSecrets(opts Opts) error {
	var (
		ns       = opts.ValueNamespace
		repoPath = opts.ValuePath
		remote   = opts.ValueRemote
	)

	repo, err := open(repoPath)
	if err != nil {
		return err
	}

	err = sync(repo, remote, ns)
	if err != nil {
		return err
	}

	return nil
}

func checkMasterPasswordCache(opts Opts) error {
	opts.ValueMasterFile = "/dev/null"

	_, err := readMasterKey(opts)
	if err != nil {
		return karma.Format(err, "unable to read master key")
	}

	return nil
}

func readMasterKey(opts Opts) ([]byte, error) {
	var (
		useCache          = opts.FlagUseMasterCache
		cacheFileName     = opts.ValueMasterCachePath
		masterKeyFileName = opts.ValueMasterFile
		repoPath          = opts.ValuePath
	)

	if len(globalMasterKey) > 0 {
		return globalMasterKey, nil
	}

	if useCache {
		masterKey, err := getMasterKeyFromCache(cacheFileName, repoPath)
		if err != nil {
			return nil, karma.Format(
				err,
				"unable to retrieve master key from cache",
			)
		}

		if masterKey != nil {
			return masterKey, nil
		}
	}

	var masterKey []byte
	var err error

	if masterKeyFileName == "" {
		if stat, err := os.Stdin.Stat(); err != nil {
			return nil, karma.Format(err, "unable to stat stdin")
		} else {
			if (stat.Mode() & os.ModeCharDevice) == 0 {
				return nil, karma.Format(
					err, "interactive terminal required, pipe given",
				)
			}
		}

		fmt.Fprint(os.Stderr, "Enter master password: ")
		masterKey, err = terminal.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, karma.Format(
				err, "unable to read master password from terminal",
			)
		}
	} else {
		masterKey, err = ioutil.ReadFile(masterKeyFileName)
		if err != nil {
			return nil, karma.Format(
				err, "unable to read master password from file",
			)
		}
	}

	if len(masterKey) < 1 {
		return nil, fmt.Errorf("master key unable to be empty")
	}

	if useCache {
		err := storeMasterKeyCache(repoPath, masterKey, cacheFileName)
		if err != nil {
			return nil, karma.Format(
				err,
				"unable to store master key cache",
			)
		}
	}

	globalMasterKey = masterKey

	return masterKey, nil
}

func getSecretsFromRepo(
	repo *repo, ns string, masterKey []byte,
) ([]secret, error) {
	refs, err := repo.list(ns)
	if err != nil {
		return nil, karma.Format(err, "unable to get tokens")
	}

	//sort.Sort(refs)

	secrets := []secret{}

	for _, ref := range refs {
		if ref.name != ref.token().name {
			continue
		}

		hexToken := strings.TrimPrefix(ref.name, ns)
		ciphertext, err := repo.cat(ref.hash)
		if err != nil {
			return nil, karma.Format(
				err,
				"unable to get ciphertext from %q",
				ref.name,
			)
		}

		encryptedToken, err := hex.DecodeString(hexToken)
		if err != nil {
			return nil, karma.Format(
				err,
				"unable to decode hex token %q", hexToken,
			)
		}

		secret, err := decryptBlob(encryptedToken, ciphertext, masterKey)
		if err != nil {
			if err != errInvalidHMAC {
				return nil, karma.Format(
					err,
					"unable to decrypt blob for token %q", hexToken,
				)
			}
		} else {
			secret.ref = ref
			secrets = append(secrets, *secret)
		}
	}

	return secrets, nil
}

func storeMasterKeyCache(
	repoPath string,
	masterKey []byte,
	cacheFileName string,
) error {
	machineKey, err := getUniqueMachineID()
	if err != nil {
		return karma.Format(err, "unable to obtain machine key")
	}

	encryptedToken, ciphertext, err := encryptBlob(
		[]byte(filepath.Base(cacheFileName)), masterKey, machineKey,
	)

	targetCacheName := filepath.Join(
		filepath.Dir(cacheFileName),
		filepath.Base(cacheFileName)+
			"."+getHash(repoPath)+
			"."+hex.EncodeToString(encryptedToken),
	)

	err = os.MkdirAll(filepath.Dir(targetCacheName), 0700)
	if err != nil {
		return karma.Format(
			err,
			"unable to create dir for %q", targetCacheName,
		)
	}

	file, err := os.OpenFile(
		targetCacheName, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600,
	)
	if err != nil {
		return karma.Format(
			err,
			"unable to create cache file %q for master key",
			targetCacheName,
		)
	}

	_, err = file.Write(ciphertext.getBody())
	if err != nil {
		return karma.Format(
			err,
			"unable to write encrypted master key to %q",
			targetCacheName,
		)
	}

	err = file.Close()
	if err != nil {
		return karma.Format(
			err,
			"unable to close cache file %q", targetCacheName,
		)
	}

	return nil
}

func getMasterKeyFromCache(cacheFileName string, repoPath string) ([]byte, error) {
	machineKey, err := getUniqueMachineID()
	if err != nil {
		return nil, karma.Format(err, "unable to obtain machine key")
	}

	repoHash := getHash(repoPath)
	candidates, err := filepath.Glob(
		cacheFileName + "." + repoHash + ".*",
	)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to glob for '%s.%s.*'", cacheFileName, repoHash,
		)
	}

	for _, candidate := range candidates {
		hexToken := strings.TrimPrefix(
			candidate,
			cacheFileName+"."+repoHash+".",
		)

		encryptedKey, err := ioutil.ReadFile(candidate)
		if err != nil {
			return nil, karma.Format(
				err,
				"unable to read encrypted master key from %q",
				candidate,
			)
		}

		encryptedToken, err := hex.DecodeString(hexToken)
		if err != nil {
			return nil, karma.Format(
				err,
				"unable to decode hex token %q", hexToken,
			)
		}

		secret, err := decryptBlob(encryptedToken, encryptedKey, machineKey)
		if err != nil {
			if err != errInvalidHMAC {
				return nil, karma.Format(
					err,
					"unable to decrypt master key from %q",
					candidate,
				)
			}

			continue
		}

		masterKey, err := ioutil.ReadAll(secret.stream)
		if err != nil {
			return nil, karma.Format(
				err,
				"unable to decrypt master key stream from %q",
				candidate,
			)
		}

		if len(masterKey) < 1 {
			return nil, fmt.Errorf(
				"empty key specified in %q",
				candidate,
			)
		}

		return masterKey, nil
	}

	return nil, nil
}

func getUniqueMachineID() ([]byte, error) {
	contents, err := ioutil.ReadFile("/etc/machine-id")
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to read /etc/machine-id",
		)
	}

	return bytes.TrimSpace(contents), nil
}

func getHash(value string) string {
	sha := sha256.New()
	sha.Write([]byte(value))
	return hex.EncodeToString(sha.Sum(nil))
}
