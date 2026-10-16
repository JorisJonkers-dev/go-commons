package testlint_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/JorisJonkers-dev/go-commons/testlint"
)

func TestTestNameFlagsNamesOfOneOrTwoWordsAndPassesSentences(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), testlint.TestName(), "names")
}

func TestClosureTableFlagsTablesOfFuncsThatNeverCallTRun(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), testlint.ClosureTable(), "tables")
}
