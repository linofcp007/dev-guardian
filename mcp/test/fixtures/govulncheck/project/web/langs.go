package web

import "golang.org/x/text/language"

// Langs calls ParseAcceptLanguage, vulnerable in x/text v0.3.7 (GO-2022-1059).
func Langs(header string) []language.Tag {
	tags, _, _ := language.ParseAcceptLanguage(header)
	return tags
}
