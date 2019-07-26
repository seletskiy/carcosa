package main

import (
	"io/ioutil"
	"strings"

	"github.com/reconquest/karma-go"

	git "gopkg.in/src-d/go-git.v4"
	git_config "gopkg.in/src-d/go-git.v4/config"
	git_plumbing "gopkg.in/src-d/go-git.v4/plumbing"
	git_transport "gopkg.in/src-d/go-git.v4/plumbing/transport"
)

var ErrNoRepo = git.ErrRepositoryNotExists

type repo struct {
	path string
	git  *git.Repository
}

func clone(url string, path string, auths auths) (*repo, error) {
	auth, err := auths.get(path)
	if err != nil {
		return nil, err
	}

	git, err := git.PlainClone(path, false, &git.CloneOptions{
		NoCheckout: true,
		Auth:       auth,
		URL:        url,
	})
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to clone git repository %q to %q", url, path,
		)
	}

	return &repo{
		path: path,
		git:  git,
	}, nil
}

func open(path string) (*repo, error) {
	git, err := git.PlainOpen(path)
	if err != nil {
		return nil, karma.Format(err, "unable to open git repository %q", path)
	}

	return &repo{
		path: path,
		git:  git,
	}, nil
}

func (repo *repo) update(ref ref) error {
	log.Debugf("{update} %s > %s", ref.hash, ref.name)

	err := repo.git.Storer.SetReference(
		git_plumbing.NewReferenceFromStrings(ref.name, ref.hash),
	)
	if err != nil {
		return karma.Format(
			err,
			"unable to update reference %q -> %q",
			ref.name,
			ref.hash,
		)
	}

	return nil
}

func (repo *repo) delete(ref ref) error {
	log.Tracef("{delete} %s - %s", ref.hash, ref.name)

	err := repo.git.Storer.RemoveReference(
		git_plumbing.ReferenceName(ref.name),
	)
	if err != nil {
		return karma.Format(
			err,
			"unable to delete reference %q",
			ref.name,
		)
	}

	return nil
}

func (repo *repo) write(data []byte) (string, error) {
	var blob git_plumbing.MemoryObject

	blob.SetType(git_plumbing.BlobObject)
	blob.Write(data)

	hash, err := repo.git.Storer.SetEncodedObject(&blob)
	if err != nil {
		return "", karma.Format(
			err,
			"unable to set encoded object (len=%d)",
			len(data),
		)
	}

	return hash.String(), nil
}

func (repo *repo) list(ns string) (refs, error) {
	log.Tracef("{list} %s ?", ns)

	list, err := repo.git.References()
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to list references",
		)
	}

	var refs refs

	defer list.Close()
	defer func() { log.Tracef("{list} %s = %d refs", ns, len(refs)) }()

	return refs, list.ForEach(
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

func (repo *repo) auth(name string, auths auths) (git_transport.AuthMethod, error) {
	remote, err := repo.git.Remote(name)
	if err != nil {
		return nil, err
	}

	url := remote.Config().URLs[0]

	log.Debugf("{auth} remote %q | url %q", name, url)

	auth, err := auths.get(url)
	if err != nil {
		return nil, err
	}

	return auth, nil
}

func (repo *repo) pull(name string, spec refspec, auths auths) error {
	log.Debugf("{pull} %s %s", name, spec.to())

	auth, err := repo.auth(name, auths)
	if err != nil {
		return err
	}

	err = repo.git.Fetch(&git.FetchOptions{
		Auth:       auth,
		RemoteName: name,
		RefSpecs:   []git_config.RefSpec{git_config.RefSpec(spec.to())},
	})
	switch err {
	case nil:
		return nil
	case git.NoErrAlreadyUpToDate:
		return nil
	case git_transport.ErrEmptyRemoteRepository:
		log.Infof("{pull} remote repository is empty")
		return nil
	default:
		return karma.Format(
			err,
			"unable to fetch remote %q",
			name,
		)
	}
}

func (repo *repo) push(name string, spec refspec, auths auths) error {
	log.Debugf("{push} %s %s", name, spec.from())

	auth, err := repo.auth(name, auths)
	if err != nil {
		return err
	}

	err = repo.git.Push(&git.PushOptions{
		Auth:       auth,
		RemoteName: name,
		RefSpecs:   []git_config.RefSpec{git_config.RefSpec(spec.from())},
		Prune:      true,
	})
	switch err {
	case nil:
		return nil
	case git.NoErrAlreadyUpToDate:
		log.Infof("{push} remote repository is up-to-date")
		return nil
	default:
		return karma.Format(
			err,
			"unable to push to remote %q",
			name,
		)
	}
}

func (repo *repo) cat(hash string) ([]byte, error) {
	log.Tracef("{cat} %s ?", hash)

	blob, err := repo.git.BlobObject(git_plumbing.NewHash(hash))
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to get blob %q",
			hash,
		)
	}

	reader, err := blob.Reader()
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to get reader for blob %q",
			hash,
		)
	}

	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to read blob contents %q",
			hash,
		)
	}

	log.Tracef("{cat} %s = %d bytes", hash, len(data))

	return data, nil
}
