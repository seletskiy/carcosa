package carcosa

import (
	"fmt"
	"os"
	"strings"
)

const (
	external = "="
	addition = "+"
	deletion = "-"
)

type ref struct {
	name string
	hash string
	stat os.FileInfo
}

func (ref ref) token() ref {
	ref.name = strings.TrimRight(
		ref.name,
		strings.Join(
			[]string{external, addition, deletion},
			"",
		),
	)

	return ref
}

func (ref *ref) is(mark string) bool {
	return strings.HasSuffix(ref.name, mark)
}

func (ref ref) as(mark string) ref {
	ref.name = ref.token().name + mark
	return ref
}

type refspec string

func (ns refspec) to() string {
	return fmt.Sprintf("%[1]s/*:%[1]s/*=", strings.TrimSuffix(string(ns), "/"))
}

func (ns refspec) from() string {
	return fmt.Sprintf("%[1]s/*=:%[1]s/*", strings.TrimSuffix(string(ns), "/"))
}

type refs []ref
