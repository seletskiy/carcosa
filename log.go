package main

import (
	"fmt"
	"regexp"

	"github.com/kovetskiy/lorg"
	"github.com/reconquest/colorgful"
)

var log *lorg.Log

func init() {
	log = lorg.NewLog()

	theme := colorgful.MustApplyDefaultTheme(
		`${time:2006-01-02 15:04:05.000} ${level:%s:left:true} %s`,
		colorgful.Default,
	)

	log.SetFormat(theme)
	log.SetOutput(theme)

	log.SetIndentLines(true)
	log.SetShiftIndent(len(
		regexp.MustCompile(`\x1b\[[^m]+m`).ReplaceAllString(
			fmt.Sprintf(theme.Render(lorg.LevelWarning, ""), ""), "",
		),
	))
}
