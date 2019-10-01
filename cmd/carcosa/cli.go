package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"syscall"

	"github.com/reconquest/karma-go"
	"github.com/seletskiy/carcosa/pkg/carcosa"
	"github.com/seletskiy/carcosa/pkg/carcosa/auth"
	"github.com/seletskiy/carcosa/pkg/carcosa/cache"
	"golang.org/x/crypto/ssh/terminal"
)

type Opts struct {
	ArgToken             string   `docopt:"<token>"`
	ArgURL               string   `docopt:"<url>"`
	ModeInit             bool     `docopt:"--init"`
	ModeSync             bool     `docopt:"--sync"`
	ModeAdd              bool     `docopt:"--add"`
	ModeModify           bool     `docopt:"--modify"`
	ModeGet              bool     `docopt:"--get"`
	ModeList             bool     `docopt:"--list"`
	ModeRemove           bool     `docopt:"--remove"`
	ModeKeycheck         bool     `docopt:"--keycheck"`
	ValueNamespace       string   `docopt:"-s"`
	ValuePath            string   `docopt:"-p"`
	ValueRemote          string   `docopt:"-r"`
	ValueMasterCachePath string   `docopt:"-f"`
	ValueMasterFile      string   `docopt:"-k"`
	ValueEditor          string   `docopt:"-e"`
	ValueAuth            []string `docopt:"-a"`
	FlagNoSync           bool     `docopt:"-n"`
	FlagNoPush           bool     `docopt:"-n"`
	FlagSyncFirst        bool     `docopt:"-y"`
	FlagUseMasterCache   bool     `docopt:"-c"`
	FlagVerbose          int      `docopt:"-v"`
}

type cli struct {
	carcosa *carcosa.Carcosa
	cache   *cache.Cache
}

func (cli *cli) run(opts Opts) error {
	auth := auth.New()

	for _, definition := range opts.ValueAuth {
		err := auth.Add(definition)
		if err != nil {
			return err
		}
	}

	switch {
	case opts.ModeInit:
		return cli.init(opts, auth)
	case opts.ModeSync:
		return cli.sync(opts, auth)
	case opts.ModeKeycheck:
		return cli.keycheck(opts)
	}

	var fn func(Opts) error

	switch {
	case opts.ModeAdd:
		fn = cli.add
	case opts.ModeGet:
		fn = cli.get
	case opts.ModeList:
		fn = cli.list
	case opts.ModeModify:
		fn = cli.modify
	case opts.ModeRemove:
		fn = cli.remove
	}

	synced := func(fn func(opts Opts) error) func(opts Opts) error {
		return func(opts Opts) error {
			err := cli.sync(opts, auth)
			if err != nil {
				return err
			}

			return fn(opts)
		}
	}

	if opts.FlagSyncFirst {
		fn = synced(fn)
	}

	return fn(opts)
}

func (cli *cli) init(opts Opts, auth auth.Auth) error {
	err := cli.carcosa.Init(opts.ArgURL, opts.ValueRemote, auth)
	if err != nil {
		return err
	}

	opts.FlagNoPush = true

	return cli.sync(opts, auth)
}

func (cli *cli) sync(opts Opts, auth auth.Auth) error {
	stats, err := cli.carcosa.Sync(opts.ValueRemote, auth, !opts.FlagNoPush)
	if err != nil {
		return err
	}

	log.Infof(
		"{sync} done: sent: +%d -%d | recv +%d -%d",
		stats.Thys.Add, stats.Thys.Del,
		stats.Ours.Add, stats.Ours.Del,
	)

	return nil
}

func (cli *cli) key(opts Opts) ([]byte, error) {
	if opts.ValueMasterFile != "" {
		key, err := ioutil.ReadFile(opts.ValueMasterFile)
		if err != nil {
			return nil, karma.Format(
				err,
				"unable to read master password from file",
			)
		}

		return key, nil
	}

	query := func() ([]byte, error) {
		stat, err := os.Stdin.Stat()
		if err != nil {
			return nil, karma.Format(err, "unable to stat stdin")
		}

		if (stat.Mode() & os.ModeCharDevice) == 0 {
			return nil, karma.Format(err, "interactive terminal required")
		}

		fmt.Fprint(os.Stderr, "Enter master password: ")
		defer fmt.Fprintln(os.Stderr)

		key, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil, karma.Format(
				err, "unable to read master password from terminal",
			)
		}

		return key, nil
	}

	cached := func(fn func() ([]byte, error)) func() ([]byte, error) {
		return func() ([]byte, error) {
			key, err := cli.cache.Get(opts.ValuePath)
			if err != nil {
				return nil, karma.Format(
					err,
					"unable to retrieve master key from cache",
				)
			}

			if key != nil {
				return key, nil
			}

			key, err = fn()
			if err != nil {
				return nil, err
			}

			err = cli.cache.Set(opts.ValuePath, key)
			if err != nil {
				return nil, karma.Format(
					err,
					"unable to store master key in cache",
				)
			}

			return key, nil
		}
	}

	if opts.ModeKeycheck {
		query = func() ([]byte, error) { return nil, nil }
	}

	if opts.FlagUseMasterCache {
		query = cached(query)
	}

	key, err := query()
	if err != nil {
		return nil, err
	}

	if len(key) == 0 {
		return nil, fmt.Errorf("master key is empty")
	}

	return key, nil
}

func (cli *cli) add(opts Opts) error {
	plaintext, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return karma.Format(err, "unable to read secret body")
	}

	key, err := cli.key(opts)
	if err != nil {
		return err
	}

	err = cli.carcosa.Add([]byte(opts.ArgToken), plaintext, key)
	if err != nil {
		return err
	}

	return nil
}

func (cli *cli) remove(opts Opts) error {
	key, err := cli.key(opts)
	if err != nil {
		return err
	}

	return cli.carcosa.Remove([]byte(opts.ArgToken), key)
}

func (cli *cli) get(opts Opts) error {
	key, err := cli.key(opts)
	if err != nil {
		return err
	}

	stream, err := cli.carcosa.Get([]byte(opts.ArgToken), key)
	if err != nil {
		return err
	}

	if stream == nil {
		return karma.
			Describe("token", opts.ArgToken).
			Reason("secret not found")
	}

	_, err = io.Copy(os.Stdout, stream)
	if err != nil {
		return karma.Format(
			err,
			"unable to output secret",
		)
	}

	return nil
}

func (cli *cli) modify(opts Opts) error {
	key, err := cli.key(opts)
	if err != nil {
		return err
	}

	stream, err := cli.carcosa.Get([]byte(opts.ArgToken), key)
	if err != nil {
		return err
	}

	plaintext, err := ioutil.ReadAll(stream)
	if err != nil {
		return karma.Format(
			err,
			"unable to read secret",
		)
	}

	plaintext, err = editor(opts.ValueEditor, plaintext)
	if err != nil {
		return err
	}

	err = cli.carcosa.Remove([]byte(opts.ArgToken), key)
	if err != nil {
		return err
	}

	err = cli.carcosa.Add([]byte(opts.ArgToken), plaintext, key)
	if err != nil {
		return err
	}

	return nil
}

func (cli *cli) list(opts Opts) error {
	key, err := cli.key(opts)
	if err != nil {
		return err
	}

	secrets, err := cli.carcosa.List(key)
	if err != nil {
		return err
	}

	for _, secret := range secrets {
		_, err := fmt.Println(string(secret.Token))
		if err != nil {
			return err
		}
	}

	return nil
}

func (cli *cli) keycheck(opts Opts) error {
	_, err := cli.key(opts)
	if err != nil {
		return err
	}

	return nil
}
