package auth

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"github.com/reconquest/karma-go"
	"golang.org/x/crypto/ssh"
	git_transport "gopkg.in/src-d/go-git.v4/plumbing/transport"
	git_ssh "gopkg.in/src-d/go-git.v4/plumbing/transport/ssh"
)

type Auth map[string]git_transport.AuthMethod

func New() Auth {
	return Auth{}
}

func (auth Auth) Add(definition string) error {
	var method git_transport.AuthMethod

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

		method = &git_ssh.PublicKeys{
			Signer: signer,
			HostKeyCallbackHelper: git_ssh.HostKeyCallbackHelper{
				HostKeyCallback: func(
					hostname string,
					remote net.Addr,
					key ssh.PublicKey,
				) error {
					return nil
				},
			},
		}

	default:
		return fmt.Errorf(
			"unsupported auth definition: %q",
			definition,
		)
	}

	auth[spec[0]] = method

	return nil
}

func (auth Auth) Get(path string) (git_transport.AuthMethod, error) {
	endpoint, err := git_transport.NewEndpoint(path)
	if err != nil {
		return nil, karma.
			Describe("endpoint", path).
			Format(
				err,
				"unable to parse endpoint",
			)
	}

	method := auth[endpoint.Protocol]
	if method == nil {
		return nil, nil
	}

	switch method := method.(type) {
	case *git_ssh.PublicKeys:
		if endpoint.User != "" {
			method.User = endpoint.User
		} else {
			method.User = "git"
		}

		auth[endpoint.Protocol] = method
	}

	return method, nil
}
