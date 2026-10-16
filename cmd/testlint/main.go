// Command testlint runs the estate's test lints over packages and their tests:
//
//	go tool testlint ./...
package main

import (
	"golang.org/x/tools/go/analysis/multichecker"

	"github.com/JorisJonkers-dev/go-commons/testlint"
)

func main() { multichecker.Main(testlint.TestName(), testlint.ClosureTable()) }
