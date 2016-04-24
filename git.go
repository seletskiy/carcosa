package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/seletskiy/hierr"
)

type git struct {
	path string
}

type ref struct {
	name string
	hash string
}

func (repo *git) updateRef(refName string, pointer string) error {
	output, err := exec.Command(
		"git", "update-ref", refName, pointer,
	).CombinedOutput()
	if err != nil {
		return hierr.Errorf(
			err,
			"error executing git update-ref\n%s", bytes.TrimSpace(output),
		)
	}

	return nil
}

func (repo *git) removeRef(refName string) error {
	output, err := exec.Command(
		"git", "update-ref", "-d", refName,
	).CombinedOutput()
	if err != nil {
		return hierr.Errorf(
			err,
			"error executing git update-ref -d\n%s", bytes.TrimSpace(output),
		)
	}

	return nil
}

func (repo *git) writeObject(data []byte) (string, error) {
	cmd := exec.Command(
		"git", "hash-object", "-w", "--stdin",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", hierr.Errorf(err, "can't get stdin for git hash-object")
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", hierr.Errorf(err, "can't get stdout for git hash-object")
	}

	err = cmd.Start()
	if err != nil {
		return "", hierr.Errorf(
			err,
			"can't run git hash-object",
		)
	}

	_, err = stdin.Write(data)
	if err != nil {
		return "", hierr.Errorf(err, "can't write data to git hash-object")
	}

	err = stdin.Close()
	if err != nil {
		return "", hierr.Errorf(err, "can't close git hash-object stdin")
	}

	output, err := ioutil.ReadAll(stdout)
	if err != nil {
		return "", hierr.Errorf(
			err,
			"can't read git hash-object result",
		)
	}

	err = cmd.Wait()
	if err != nil {
		return "", hierr.Errorf(err, "can't wait for git hash-object")
	}

	return strings.TrimSpace(string(output)), nil
}

func (repo *git) listRefs(namespace string) ([]ref, error) {
	output, err := makeCommandInDir(
		repo.path, "git", "show-ref",
	).CombinedOutput()
	if err != nil {
		return nil, hierr.Errorf(
			err,
			"error executing git show-ref\n%s", bytes.TrimSpace(output),
		)
	}

	refList := []ref{}
	scanner := bufio.NewScanner(bytes.NewBuffer(output))
	for scanner.Scan() {
		var hash, name string

		_, err := fmt.Sscanf(scanner.Text(), "%s %s", &hash, &name)
		if err != nil {
			return nil, hierr.Errorf(err, "can't read from git show-ref")
		}

		if !strings.HasPrefix(name, namespace) {
			continue
		}

		refList = append(refList, ref{
			name: name,
			hash: hash,
		})
	}

	return refList, nil
}

func (repo *git) isGitRepo() bool {
	err := makeCommandInDir(
		repo.path, "git", "rev-parse", "--git-dir",
	).Run()
	if err != nil {
		return false
	}

	return true
}

func (repo *git) clone(remote string) error {
	cmd := exec.Command(
		"git", "clone", "--depth=1", "--bare", "-n", remote, repo.path,
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return hierr.Errorf(
			err,
			"can't run git clone '%s' -> '%s'", remote, repo.path,
		)
	}

	return nil
}

func (repo *git) fetch(remote string, ref string) error {
	cmd := makeCommandInDir(
		repo.path, "git", "fetch", remote, ref,
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return hierr.Errorf(
			err,
			"can't run git fetch '%s' '%s'", remote, ref,
		)
	}

	return nil
}

func (repo *git) push(remote string, ref string) error {
	cmd := exec.Command(
		"git", "push", "--prune", remote, ref,
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return hierr.Errorf(
			err,
			"can't run git push '%s' '%s'", remote, ref,
		)
	}

	return nil
}

func (repo *git) catFile(hash string) ([]byte, error) {
	output, err := makeCommandInDir(
		repo.path, "git", "cat-file", "-p", hash,
	).CombinedOutput()
	if err != nil {
		return nil, hierr.Errorf(
			err,
			"error executing git cat-file\n%s", bytes.TrimSpace(output),
		)
	}

	return output, nil
}

func makeCommandInDir(dir, name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	return cmd
}
