package main

import (
	"fmt"
	"strings"
)

type remoteError struct {
	error
}

func fetchRemote(repo git, remote string, refNamespace string) error {
	if !repo.isGitRepo() {
		if remote == "origin" {
			return fmt.Errorf(
				"directory is not a git repo and remote is not specified",
			)
		}

		err := repo.clone(remote)
		if err != nil {
			return fmt.Errorf(
				"can't clone git repo '%s': %s", remote, err,
			)
		}
	}

	refSpec := fmt.Sprintf(
		"%[1]s/*:%[1]s/*",
		strings.TrimSuffix(refNamespace, "/"),
	)

	err := repo.fetch(remote, refSpec)
	if err != nil {
		return remoteError{fmt.Errorf(
			"can't pull remote '%s': %s", remote, err,
		)}
	}

	return nil
}

func pushRemote(repo git, remote string, refNamespace string) error {
	refSpec := fmt.Sprintf(
		"%[1]s/*:%[1]s/*",
		strings.TrimSuffix(refNamespace, "/"),
	)

	err := repo.push(remote, refSpec)
	if err != nil {
		return remoteError{fmt.Errorf(
			"can't push to remote git repo '%s': %s", remote, err,
		)}
	}

	return nil
}
