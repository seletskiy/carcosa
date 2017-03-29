package main

import (
	"fmt"
	"strings"

	"github.com/reconquest/hierr-go"
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
			return hierr.Errorf(
				err,
				"can't clone git repo '%s'", remote,
			)
		}
	}

	refSpec := fmt.Sprintf(
		"%[1]s/*:%[1]s/*",
		strings.TrimSuffix(refNamespace, "/"),
	)

	err := repo.fetch(remote, refSpec)
	if err != nil {
		return remoteError{hierr.Errorf(
			err,
			"can't pull remote '%s'", remote,
		)}
	}

	return nil
}

func pushRemote(
	repo git,
	remote string,
	refNamespace string,
	prune bool,
) error {
	refSpec := fmt.Sprintf(
		"%[1]s/*:%[1]s/*",
		strings.TrimSuffix(refNamespace, "/"),
	)

	err := repo.push(remote, refSpec, prune)
	if err != nil {
		return remoteError{hierr.Errorf(
			err,
			"can't push to remote git repo '%s'", remote,
		)}
	}

	return nil
}
