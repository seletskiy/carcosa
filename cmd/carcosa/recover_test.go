package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/docopt/docopt-go"
	"github.com/seletskiy/carcosa/pkg/carcosa/cache"
	"github.com/seletskiy/carcosa/pkg/carcosa/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func recoveryFixture(t *testing.T) (*cli, Opts, func()) {
	t.Helper()

	dir, err := ioutil.TempDir("", "carcosa-recovery-test-")
	require.NoError(t, err)
	cleanup := func() { os.RemoveAll(dir) }

	opts := Opts{
		ModeRecoverMaster:    true,
		ValuePath:            filepath.Join(dir, "nonexistent-repo"),
		ValueMasterCachePath: filepath.Join(dir, "cache"),
		ValueMasterKeyPath:   filepath.Join(dir, "machine-key"),
	}
	if err := ioutil.WriteFile(opts.ValueMasterKeyPath, []byte("test machine key\n"), 0600); err != nil {
		cleanup()
		t.Fatal(err)
	}

	return &cli{
		cache: cache.NewDefault(vault.NewMaster(
			opts.ValueMasterCachePath, opts.ValueMasterKeyPath,
		)),
	}, opts, cleanup
}

func recoveryRecord(opts Opts) string {
	hash := sha256.Sum256([]byte(opts.ValuePath))
	return filepath.Join(opts.ValueMasterCachePath, fmt.Sprintf("%x.key", hash))
}

func recoverySnapshot(t *testing.T, opts Opts) map[string][]byte {
	t.Helper()

	result := map[string][]byte{}
	files, err := ioutil.ReadDir(opts.ValueMasterCachePath)
	if os.IsNotExist(err) {
		return result
	}
	require.NoError(t, err)
	for _, file := range files {
		data, err := ioutil.ReadFile(filepath.Join(opts.ValueMasterCachePath, file.Name()))
		require.NoError(t, err)
		result[file.Name()] = data
	}
	return result
}

func TestRecoverMasterExactBytes(t *testing.T) {
	for _, test := range []struct {
		name     string
		password []byte
	}{
		{"text", []byte("synthetic master password")},
		{"long", bytes.Repeat([]byte("long master password"), 100)},
		{"binary_and_whitespace", []byte(" \tpassword\x00\xff\r\n ")},
	} {
		t.Run(test.name, func(t *testing.T) {
			app, opts, cleanup := recoveryFixture(t)
			defer cleanup()
			require.NoError(t, app.cache.Set(opts.ValuePath, test.password))
			before := recoverySnapshot(t, opts)

			var output bytes.Buffer
			require.NoError(t, app.recoverMaster(opts, &output))
			assert.Equal(t, test.password, output.Bytes())
			assert.Equal(t, before, recoverySnapshot(t, opts), "recovery must not change the cache")
		})
	}
}

func TestRecoverMasterFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, *cli, *Opts)
		want   string
	}{
		{
			name: "missing_cache",
			change: func(t *testing.T, app *cli, opts *Opts) {
				require.NoError(t, os.RemoveAll(opts.ValueMasterCachePath))
			},
			want: "cache is missing or empty",
		},
		{
			name: "different_repo_path",
			change: func(t *testing.T, app *cli, opts *Opts) {
				opts.ValuePath += "-moved"
			},
			want: "cache is missing or empty",
		},
		{
			name: "empty_password",
			change: func(t *testing.T, app *cli, opts *Opts) {
				require.NoError(t, app.cache.Set(opts.ValuePath, nil))
			},
			want: "cache is missing or empty",
		},
		{
			name: "wrong_key",
			change: func(t *testing.T, app *cli, opts *Opts) {
				require.NoError(t, ioutil.WriteFile(opts.ValueMasterKeyPath, []byte("wrong key"), 0600))
			},
			want: "signature mismatch",
		},
		{
			name: "missing_key",
			change: func(t *testing.T, app *cli, opts *Opts) {
				require.NoError(t, os.Remove(opts.ValueMasterKeyPath))
			},
			want: "unable to recover master password from cache",
		},
		{
			name: "key_file_override_rejected",
			change: func(t *testing.T, app *cli, opts *Opts) {
				opts.ValueMasterFile = opts.ValueMasterKeyPath
			},
			want: "--recover-master cannot be used with -k",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			app, opts, cleanup := recoveryFixture(t)
			defer cleanup()
			require.NoError(t, app.cache.Set(opts.ValuePath, []byte("test password")))
			test.change(t, app, &opts)
			before := recoverySnapshot(t, opts)

			var output bytes.Buffer
			err := app.recoverMaster(opts, &output)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.want)
			assert.Empty(t, output.Bytes())
			assert.Equal(t, before, recoverySnapshot(t, opts), "failed recovery must not change the cache")
		})
	}
}

func TestRecoverMasterTruncatedCache(t *testing.T) {
	app, opts, cleanup := recoveryFixture(t)
	defer cleanup()
	require.NoError(t, app.cache.Set(opts.ValuePath, []byte("test password")))
	record, err := ioutil.ReadFile(recoveryRecord(opts))
	require.NoError(t, err)

	// The header contains a 32-byte token, a 16-byte IV, and a 32-byte signature.
	for size := 0; size < 80; size++ {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			require.NoError(t, ioutil.WriteFile(recoveryRecord(opts), record[:size], 0600))
			before := recoverySnapshot(t, opts)
			var output bytes.Buffer
			err := app.recoverMaster(opts, &output)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "record is too short")
			assert.Empty(t, output.Bytes())
			assert.Equal(t, before, recoverySnapshot(t, opts))
		})
	}
}

type recoveryFailingWriter struct {
	err error
}

func (writer recoveryFailingWriter) Write(data []byte) (int, error) {
	return 0, writer.err
}

func TestRecoverMasterOutputFailure(t *testing.T) {
	app, opts, cleanup := recoveryFixture(t)
	defer cleanup()
	require.NoError(t, app.cache.Set(opts.ValuePath, []byte("test password")))

	for _, writeErr := range []error{errors.New("output unavailable"), nil} {
		err := app.recoverMaster(opts, recoveryFailingWriter{err: writeErr})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to output recovered master password")
		if writeErr == nil {
			assert.Contains(t, err.Error(), io.ErrShortWrite.Error())
		} else {
			assert.Contains(t, err.Error(), writeErr.Error())
		}
	}
}

func TestRunRecoverMasterSkipsAuthAndSync(t *testing.T) {
	app, opts, cleanup := recoveryFixture(t)
	defer cleanup()
	password := []byte("test password")
	require.NoError(t, app.cache.Set(opts.ValuePath, password))
	before := recoverySnapshot(t, opts)

	// Neither invalid auth nor sync may be reached. There is no repository.
	opts.ValueAuth = []string{"invalid-auth"}
	opts.FlagSyncFirst = true
	output, err := ioutil.TempFile(filepath.Dir(opts.ValuePath), "stdout-")
	require.NoError(t, err)
	defer output.Close()
	stdout := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = stdout }()

	require.NoError(t, app.run(opts))
	data, err := ioutil.ReadFile(output.Name())
	require.NoError(t, err)
	assert.Equal(t, password, data)
	assert.Equal(t, before, recoverySnapshot(t, opts))
}

func TestParseRecoverMaster(t *testing.T) {
	parser := &docopt.Parser{HelpHandler: docopt.NoHelpHandler}
	for _, argv := range [][]string{
		{"--recover-master"},
		{"--recover-master", "-c"},
		{"--recover-master", "-p", "/repo", "-f", "/cache", "-x", "/key", "-vv"},
	} {
		args, err := parser.ParseArgs(usage, argv, "2")
		require.NoError(t, err)
		var opts Opts
		require.NoError(t, args.Bind(&opts))
		assert.True(t, opts.ModeRecoverMaster)
		if len(argv) > 2 {
			assert.Equal(t, "/repo", opts.ValuePath)
			assert.Equal(t, "/cache", opts.ValueMasterCachePath)
			assert.Equal(t, "/key", opts.ValueMasterKeyPath)
			assert.Equal(t, 2, opts.FlagVerbose)
		}
	}

	for _, argv := range [][]string{
		{"--recover-master", "-L"},
		{"--recover-master", "-G", "token"},
		{"--recover-master", "-F", "-c"},
		{"--recover-master", "-S"},
		{"--recover-master", "-y"},
	} {
		_, err := parser.ParseArgs(usage, argv, "2")
		assert.Error(t, err, "conflicting arguments: %v", argv)
	}

	// Existing commands must retain their shared path options.
	args, err := parser.ParseArgs(usage, []string{"-L", "-c", "-p", "/repo", "-f", "/cache", "-x", "/key"}, "2")
	require.NoError(t, err)
	var opts Opts
	require.NoError(t, args.Bind(&opts))
	assert.True(t, opts.ModeList)
	assert.False(t, opts.ModeRecoverMaster)
	assert.Equal(t, "/repo", opts.ValuePath)
	assert.Equal(t, "/cache", opts.ValueMasterCachePath)
	assert.Equal(t, "/key", opts.ValueMasterKeyPath)
}
