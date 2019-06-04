package main

import (
	"fmt"
	"os"
	"strings"
)

type refSuffix string

var (
	refSuffixRemote refSuffix = "="
	refSuffixAdd              = "+"
	refSuffixDel              = "-"
)

type ref struct {
	name string
	hash string
	stat os.FileInfo
}

func (ref *ref) isAdd() bool {
	return strings.HasSuffix(ref.name, refSuffixAdd)
}

func (ref *ref) isDel() bool {
	return strings.HasSuffix(ref.name, refSuffixDel)
}

func (ref *ref) isRemote() bool {
	return strings.HasSuffix(ref.name, refSuffixRemote)
}

func (ref *ref) token() string {
	return strings.TrimRight(
		ref.name,
		strings.Join(
			[]string{refSuffixRemote, refSuffixAdd, refSuffixDel},
			"",
		),
	)
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
