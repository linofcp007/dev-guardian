// Package util is the only intra-project Go package in this fixture, imported
// by go-api/main.go as "example.com/goapi/pkg/util".
//
// The file is deliberately NOT named after its directory. A Go import names a
// package DIRECTORY (`pkg/util`), never a file, so a resolver that matches an
// extension-stripped file path only ever succeeds on the accidental
// `pkg/util/util.go` spelling — and reports every ordinary Go package as
// imported by nothing. `shout.go` fails against that wrong implementation and
// passes against the right one.
//
// Adding, removing or renaming this file changes the pinned import-edge list
// in mcp/test/e2e/rulePackFixture.test.ts and the Go reachability verdict in
// mcp/test/e2e/validateFindingFixture.test.ts.
package util

import "strings"

// Shout upper-cases a string. No route, no env var, no framework.
func Shout(s string) string {
	return strings.ToUpper(s)
}
