package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// built builds the command for the test to run.
func built(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "testlint")
	if out, err := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".").CombinedOutput(); err != nil { //nolint:gosec // the test builds into its own temp dir
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func TestTheTagsFlagLintsTheTestsBehindThoseTags(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), built(t), "-tags", "integration", "./...") //nolint:gosec // the command the test built
	cmd.Dir = "testdata/tagged"
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "test name TestTagged names no behaviour") {
		t.Fatalf("the tagged test was not linted:\n%s", out)
	}
}

func TestWithoutTheTagsFlagTaggedTestsAreLeftOut(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), built(t), "./...") //nolint:gosec // the command the test built
	cmd.Dir = "testdata/tagged"
	if out, err := cmd.CombinedOutput(); err != nil || len(out) != 0 {
		t.Fatalf("testlint = %v:\n%s", err, out)
	}
}

func TestTheTagsAreReadInEitherFlagForm(t *testing.T) {
	for _, args := range [][]string{{"-tags=integration", "./..."}, {"--tags", "integration", "./..."}, {"-c", "1", "-tags", "integration", "./..."}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if got := tagsOf(args); got != "integration" {
				t.Fatalf("tagsOf = %q", got)
			}
		})
	}
}

func TestNoTagsAreReadWithoutAFlagOrAfterTheFlagsEnd(t *testing.T) {
	for _, args := range [][]string{{"./..."}, {"--", "-tags", "integration"}, {"-tags"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if got := tagsOf(args); got != "" {
				t.Fatalf("tagsOf = %q", got)
			}
		})
	}
}
