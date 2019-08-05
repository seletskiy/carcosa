package main

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/reconquest/karma-go"
	"golang.org/x/crypto/ssh"
	git_transport "gopkg.in/src-d/go-git.v4/plumbing/transport"
	git_ssh "gopkg.in/src-d/go-git.v4/plumbing/transport/ssh"
)

type auths map[string]git_transport.AuthMethod

func (auths auths) add(definition string) error {
	var auth git_transport.AuthMethod

	spec := strings.SplitN(definition, ":", 2)

	switch spec[0] {
	case "ssh":
		sshKey, err := ioutil.ReadFile(spec[1])
		if err != nil {
			return karma.
				Describe("path", spec[1]).
				Format(
					err,
					"unable to read private key file",
				)
		}

		signer, err := ssh.ParsePrivateKey([]byte(sshKey))
		if err != nil {
			return karma.Format(
				err,
				"unable to parse private key",
			)
		}

		auth = &git_ssh.PublicKeys{
			Signer: signer,
		}

	default:
		return fmt.Errorf(
			"unsupported auth definition: %q",
			definition,
		)
	}

	auths[spec[0]] = auth

	return nil
}

func (auths auths) get(path string) (git_transport.AuthMethod, error) {
	endpoint, err := git_transport.NewEndpoint(path)
	if err != nil {
		return nil, karma.
			Describe("endpoint", path).
			Format(
				err,
				"unable to parse endpoint",
			)
	}

	auth := auths[endpoint.Protocol]
	if auth == nil {
		return nil, karma.Format(
			err,
			"no auth method known for protocol %q",
			endpoint.Protocol,
		)
	}

	switch auth := auth.(type) {
	case *git_ssh.PublicKeys:
		if endpoint.User != "" {
			auth.User = endpoint.User
		} else {
			auth.User = "git"
		}
	}

	return auth, nil
}
