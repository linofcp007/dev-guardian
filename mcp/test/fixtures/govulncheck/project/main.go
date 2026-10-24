// Deliberately vulnerable: the govulncheck e2e fixture (test/e2e/govulncheckDeps.test.ts).
package main

import (
	"fmt"
	"os"

	"example.com/govulnfixture/web"
)

func main() {
	fmt.Println(web.Langs(os.Args[1]))
}
