package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
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
		return fmt.Errorf(
			"error executing git update-ref: %s\n%s", err, output,
		)
	}

	return nil
}

func (repo *git) removeRef(refName string) error {
	output, err := exec.Command(
		"git", "update-ref", "-d", refName,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"error executing git update-ref -d: %s\n%s", err, output,
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
		return "", fmt.Errorf("can't get stdin for git hash-object: %s", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("can't get stdout for git hash-object: %s", err)
	}

	err = cmd.Start()
	if err != nil {
		return "", fmt.Errorf(
			"can't run git hash-object: %s", err,
		)
	}

	_, err = stdin.Write(data)
	if err != nil {
		return "", fmt.Errorf("can't write data to git hash-object: %s", err)
	}

	err = stdin.Close()
	if err != nil {
		return "", fmt.Errorf("can't close git hash-object stdin: %s", err)
	}

	output, err := ioutil.ReadAll(stdout)
	if err != nil {
		return "", fmt.Errorf(
			"can't read git hash-object result: %s", err,
		)
	}

	err = cmd.Wait()
	if err != nil {
		return "", fmt.Errorf("can't wait for git hash-object: %s", err)
	}

	return strings.TrimSpace(string(output)), nil
}

func (repo *git) listRefs(namespace string) ([]ref, error) {
	output, err := makeCommandInDir(
		repo.path, "git", "show-ref",
	).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf(
			"error executing git show-ref: %s\n%s", err, output,
		)
	}

	refList := []ref{}
	scanner := bufio.NewScanner(bytes.NewBuffer(output))
	for scanner.Scan() {
		var hash, name string

		_, err := fmt.Sscanf(scanner.Text(), "%s %s", &hash, &name)
		if err != nil {
			return nil, fmt.Errorf("can't read from git show-ref: %s", err)
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
		return fmt.Errorf(
			"can't run git clone '%s' -> '%s': %s", remote, repo.path, err,
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
		return fmt.Errorf(
			"can't run git fetch '%s' '%s': %s", remote, ref, err,
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
		return fmt.Errorf(
			"can't run git push '%s' '%s': %s", remote, ref, err,
		)
	}

	return nil
}

func (repo *git) catFile(hash string) ([]byte, error) {
	output, err := makeCommandInDir(
		repo.path, "git", "cat-file", "-p", hash,
	).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf(
			"error executing git cat-file: %s\n%s", err, output,
		)
	}

	return output, nil
}

func makeCommandInDir(dir, name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	return cmd
}
