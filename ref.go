package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	theirs   = "="
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
			[]string{theirs, addition, deletion},
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

func (refs refs) Len() int {
	return len(refs)
}

func (refs refs) Swap(i, j int) {
	refs[i], refs[j] = refs[j], refs[i]
}

func (refs refs) Less(i, j int) bool {
	if refs[i].stat == nil {
		panic(
			fmt.Sprintf("ref %s stat is nil", refs[i].hash),
		)
	}

	if refs[j].stat == nil {
		panic(
			fmt.Sprintf("ref %s stat is nil", refs[j].hash),
		)
	}

	return refs[i].stat.ModTime().Unix() < refs[j].stat.ModTime().Unix()
}
