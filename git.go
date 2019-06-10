package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/reconquest/karma-go"

	git "gopkg.in/src-d/go-git.v4"
	git_config "gopkg.in/src-d/go-git.v4/config"
	git_plumbing "gopkg.in/src-d/go-git.v4/plumbing"
	git_transport "gopkg.in/src-d/go-git.v4/plumbing/transport"
)

type repo struct {
	path string
	git  *git.Repository
}

func open(path string) (*repo, error) {
	git, err := git.PlainOpen(path)
	if err != nil {
		return nil, err
	}

	return &repo{
		path: path,
		git:  git,
	}, nil
}

func (repo *repo) update(ref ref) error {
	output, err := repo.cmd("update-ref", ref.name, ref.hash).CombinedOutput()
	if err != nil {
		return karma.Format(
			err,
			"error executing repo update-ref\n%s", bytes.TrimSpace(output),
		)
	}

	return nil
}

func (repo *repo) delete(ref ref) error {
	output, err := repo.cmd("update-ref", "-d", ref.name).CombinedOutput()
	if err != nil {
		return karma.Format(
			err,
			"error executing repo update-ref -d\n%s", bytes.TrimSpace(output),
		)
	}

	return nil
}

func (repo *repo) write(data []byte) (string, error) {
	cmd := repo.cmd("hash-object", "-w", "--stdin")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", karma.Format(err, "can't get stdin for repo hash-object")
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", karma.Format(err, "can't get stdout for repo hash-object")
	}

	err = cmd.Start()
	if err != nil {
		return "", karma.Format(
			err,
			"can't run repo hash-object",
		)
	}

	_, err = stdin.Write(data)
	if err != nil {
		return "", karma.Format(err, "can't write data to repo hash-object")
	}

	err = stdin.Close()
	if err != nil {
		return "", karma.Format(err, "can't close repo hash-object stdin")
	}

	output, err := ioutil.ReadAll(stdout)
	if err != nil {
		return "", karma.Format(
			err,
			"can't read repo hash-object result",
		)
	}

	err = cmd.Wait()
	if err != nil {
		return "", karma.Format(err, "can't wait for repo hash-object")
	}

	return strings.TrimSpace(string(output)), nil
}

func (repo *repo) list(ns string) (refs, error) {
	references, err := repo.git.References()
	if err != nil {
		return nil, err
	}

	var refs refs

	defer references.Close()
	return refs, references.ForEach(
		func(reference *git_plumbing.Reference) error {
			ref := ref{
				name: reference.Name().String(),
				hash: reference.Hash().String(),
			}

			if !strings.HasPrefix(ref.name, ns) {
				return nil
			}

			refs = append(refs, ref)

			return nil
		},
	)
}

func (repo *repo) isGitRepo() bool {
	err := repo.cmd("rev-parse", "--repo-dir").Run()
	if err != nil {
		return false
	}

	return true
}

func (repo *repo) clone(remote string) error {
	cmd := repo.cmd("clone", "--depth=1", "--bare", "-n", remote, repo.path)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return karma.Format(
			err,
			"can't run repo clone '%s' -> '%s'", remote, repo.path,
		)
	}

	return nil
}

func (repo *repo) fetch(remote string, spec refspec) error {
	err := repo.git.Fetch(&git.FetchOptions{
		RemoteName: remote,
		RefSpecs:   []git_config.RefSpec{git_config.RefSpec(spec.to())},
	})
	switch err {
	case nil:
		return nil
	case git_transport.ErrEmptyRemoteRepository:
		log.Infof("remote repository is empty")
		return nil
	default:
		return err
	}
}

func (repo *repo) push(remote string, spec refspec) error {
	err := repo.git.Push(&git.PushOptions{
		RemoteName: remote,
		RefSpecs:   []git_config.RefSpec{git_config.RefSpec(spec.from())},
		Prune:      true,
	})
	switch err {
	case nil:
		return nil
	case git.NoErrAlreadyUpToDate:
		log.Infof("remote repository is up-to-date")
		return nil
	default:
		return err
	}
}

func (repo *repo) cat(hash string) ([]byte, error) {
	output, err := repo.cmd("cat-file", "-p", hash).CombinedOutput()
	if err != nil {
		return nil, karma.Format(
			err,
			"error executing repo cat-file\n%s", bytes.TrimSpace(output),
		)
	}

	return output, nil
}

func (repo *repo) cmd(args ...string) *exec.Cmd {
	args = append([]string{"-C", repo.path}, args...)

	command := exec.Command("git", args...)
	command.Env = []string{}

	return command
}
