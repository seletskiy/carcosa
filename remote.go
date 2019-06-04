package main

import (
	"fmt"
	"strings"

	"github.com/reconquest/karma-go"
)

type remoteError struct{ error }

func fetchRemote(repo git, remote string, refNamespace string) error {
	if !repo.isGitRepo() {
		if remote == "origin" {
			return fmt.Errorf(
				"directory is not a git repo and remote is not specified",
			)
		}

		err := repo.clone(remote)
		if err != nil {
			return karma.Format(
				err,
				"can't clone git repo '%s'", remote,
			)
		}
	}

	refSpec := fmt.Sprintf(
		"%[1]s/*:%[1]s/*%[2]s",
		strings.TrimSuffix(refNamespace, "/"),
		refSuffixRemote,
	)

	err := repo.fetch(remote, refSpec)
	if err != nil {
		return remoteError{
			karma.Format(
				err,
				"can't pull remote '%s'", remote,
			),
		}
	}

	refs, err := repo.listRefs(refNamespace)
	if err != nil {
		return err
	}

	var (
		theirs = []ref{}

		ours = map[string]bool{}
		add  = map[string]bool{}
		del  = map[string]bool{}
	)

	for _, ref := range refs {
		switch {
		case ref.isAdd():
			add[ref.token()] = true

		case ref.isDel():
			del[ref.token()] = true

		case ref.isRemote():
			theirs = append(theirs, ref)

		default:
			ours[ref.token()] = true
		}
	}

	for _, their := range theirs {
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
		"%[1]s/*%[2]s:%[1]s/*",
		strings.TrimSuffix(refNamespace, "/"),
		refSuffixRemote,
	)

	err := repo.push(remote, refSpec, prune)
	if err != nil {
		return remoteError{
			karma.Format(
				err,
				"can't push to remote git repo '%s'", remote,
			),
		}
	}

	return nil
}
