// Command testlint runs the estate's test lints over packages and their tests:
//
//	go tool testlint ./...
//	go tool testlint -tags integration ./...
package main

import (
	"os"
	"strings"

	"golang.org/x/tools/go/analysis/multichecker"

	"github.com/JorisJonkers-dev/go-commons/testlint"
)

func main() {
	// The analysis driver keeps -tags only as a flag with no effect; packages load with GOFLAGS.
	if tags := tagsOf(os.Args[1:]); tags != "" {
		_ = os.Setenv("GOFLAGS", strings.TrimSpace(os.Getenv("GOFLAGS")+" -tags="+tags))
	}
	multichecker.Main(testlint.TestName(), testlint.ClosureTable())
}

// tagsOf is the value of a -tags flag in args, or empty.
func tagsOf(args []string) string {
	for i, a := range args {
		if a == "--" {
			return ""
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "tags" {
			continue
		}
		if hasValue {
			return value
		}
		if i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
