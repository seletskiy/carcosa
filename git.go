package main

import (
	"io/ioutil"
	"strings"

	"github.com/reconquest/karma-go"
	"golang.org/x/crypto/ssh"

	git "gopkg.in/src-d/go-git.v4"
	git_config "gopkg.in/src-d/go-git.v4/config"
	git_plumbing "gopkg.in/src-d/go-git.v4/plumbing"
	git_transport "gopkg.in/src-d/go-git.v4/plumbing/transport"
	git_ssh "gopkg.in/src-d/go-git.v4/plumbing/transport/ssh"
)

type repo struct {
	path string
	git  *git.Repository
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

//func (repo *repo) clone(remote string) error {
//    cmd := repo.cmd("clone", "--depth=1", "--bare", "-n", remote, repo.path)

//    cmd.Stdout = os.Stdout
//    cmd.Stderr = os.Stderr

//    err := cmd.Run()
//    if err != nil {
//        return karma.Format(
//            err,
//            "can't run repo clone '%s' -> '%s'", remote, repo.path,
//        )
//    }

//    return nil
//}

func (repo *repo) auth() git_transport.AuthMethod {
	var auth git_transport.AuthMethod

	path := "/home/operator/.ssh/id_rsa"
	sshKey, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(sshKey))
	if err != nil {
		panic(err)
	}
	auth = &git_ssh.PublicKeys{
		User:   "git",
		Signer: signer,
	}

	return auth
}

func (repo *repo) pull(remote string, spec refspec) error {
	log.Debugf("{pull} %s %s", remote, spec.to())

	err := repo.git.Fetch(&git.FetchOptions{
		Auth:       repo.auth(),
		RemoteName: remote,
		RefSpecs:   []git_config.RefSpec{git_config.RefSpec(spec.to())},
	})
	switch err {
	case nil:
		return nil
	case git.NoErrAlreadyUpToDate:
		return nil
	case git_transport.ErrEmptyRemoteRepository:
		log.Infof("remote repository is empty")
		return nil
	default:
		return karma.Format(
			err,
			"unable to fetch remote %q",
			remote,
		)
	}
}

func (repo *repo) push(remote string, spec refspec) error {
	log.Debugf("{push} %s %s", remote, spec.from())

	rem, err := repo.git.Remote(remote)
	if err != nil {
		return err
	}

	rem.Config().Fetch = []git_config.RefSpec{git_config.RefSpec(spec.to())}
	err = rem.Push(&git.PushOptions{
		Auth:       repo.auth(),
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
		return karma.Format(
			err,
			"unable to push to remote %q",
			remote,
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
