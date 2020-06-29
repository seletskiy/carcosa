package main

import (
	"os"
	"os/user"
	"path/filepath"

	"github.com/docopt/docopt-go"
	"github.com/kovetskiy/lorg"
	"github.com/seletskiy/carcosa/pkg/carcosa"
	"github.com/seletskiy/carcosa/pkg/carcosa/cache"
	"github.com/seletskiy/carcosa/pkg/carcosa/vault"
)

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
    carcosa [options] [-v]... -I [-a=]... [-c] [-n] [-r <remote>] <url>
    carcosa [options] [-v]... -S [-a=]... [-c] [-n] [-r <remote>]
    carcosa [options] [-v]... -A [-a=]... [-c] [-n] <token>
    carcosa [options] [-v]... -E [-a=]... [-c] [-n] <token>
    carcosa [options] [-v]... -M [-a=]... [-c] [-n] <token> <new-token>
    carcosa [options] [-v]... -G [-a=]... [-c] [-y] <token>
    carcosa [options] [-v]... -L [-a=]... [-c] [-y]
    carcosa [options] [-v]... -R [-a=]... [-c] [-n] <token>
    carcosa [options] [-v]... -F -c

Options:
    -h --help          Show this help.
    -I --init          Initialize remote repository and fetch secrets.
    -S --sync          Sync secrets with remote storage (pull & push).
                        Push can be prohibited by using '-n' flag.
    -A --add           Add secret for specified token. Secret will be read from
                        stdin.
    -E --edit          Edit secret for specified token in place. '-e' flag can be
                        used to set editor.
    -M --move          Move/rename specified token.
    -G --get           Get secret by specified token.
    -L --list          List tokens.
    -R --remove        Remove secret by specified token.
    -F --keycheck      Check that master password cache presents and exit if it is
                        not. Suitable for scripting purposes.
    -s <ref-ns>        Use specified ref namespace.
                        [default: refs/tokens/]
    -p <path>          Set git repo path to store secrets in.
                        [default: $SECRETS_PATH]
    -n                 Do not interact with remote repo (no push / no pull).
                        For sync mode: pull, but do not push.
    -y                 Sync with remote before doing anything else.
    -r <remote>        Remote repository name to use.
                        [default: origin].
    -c                 Use cache for master password. Master password will be
                        encrypted using unique encryption key for current machine.
    -f <cache>         Cache file prefix for master password. Actual file name will
                        ends with hash suffix.
                        [default: $CACHE_PATH]
    -x <key>           Path to unique encryption key for current machine.
                        [default: $KEY_PATH]
    -k <file>          Read master key from specified file. WARNING: that can be
                        unsecure; use of fifo pipe as a file is preferable.
    -e <editor>        Use specified editor for modifying secret in place.
                        [default: $EDITOR]
    -a <auth>...       Specify authentication parameters for various remote
                        protocols.
                        Supported protocols:
                        * SSH: ssh:<private-key-path>
                        [default: ssh:$AUTH_SSH_KEY_PATH]
    -v                 Verbose output.
`

func init() {
	human, err := user.Current()
	if err != nil {
		panic(err)
	}

	home := human.HomeDir

	env := func(key, defaultValue string) {
		if os.Getenv(key) == "" {
			os.Setenv(key, defaultValue)
		}
	}

	env("SECRETS_PATH", filepath.Join(home, ".secrets"))
	env("AUTH_SSH_KEY_PATH", filepath.Join(home, ".ssh", "id_rsa"))
	env("CACHE_PATH", filepath.Join(home, ".cache", "carcosa", "master"))
	env("CONFIG_PATH", filepath.Join(home, ".config", "carcosa", "carcosa.conf"))
	env("KEY_PATH", "/etc/machine-id")

	usage = os.ExpandEnv(usage)
}

var log = carcosa.Logger()

func main() {
	args, err := docopt.ParseArgs(usage, nil, "2")
	if err != nil {
		panic(err)
	}

	log = carcosa.Logger()

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

	cli := cli{
		carcosa: carcosa.NewDefault(opts.ValuePath, opts.ValueNamespace),
		cache: cache.NewDefault(vault.NewMaster(
			opts.ValueMasterCachePath,
			opts.ValueMasterKeyPath,
		)),
	}

	err = cli.run(opts)
	if err != nil {
		log.Fatal(err)
	}
}
