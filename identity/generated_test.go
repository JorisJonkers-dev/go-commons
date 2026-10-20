package identity_test

import (
	"bytes"
	"flag"
	"io/fs"
	"os"
	"testing"

	contract "github.com/JorisJonkers-dev/identity/contract/principal"

	"github.com/JorisJonkers-dev/go-commons/internal/principalgen"
)

// go test ./identity -run TestThePrincipalTypeIsWhatThePinnedSchemaGenerates -update
var update = flag.Bool("update", false, "write principal_gen.go from the pinned contract's schema")

func TestThePrincipalTypeIsWhatThePinnedSchemaGenerates(t *testing.T) {
	schema, err := fs.ReadFile(contract.Files, "principal.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := principalgen.Generate("identity", schema)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile("principal_gen.go", want, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := os.ReadFile("principal_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("principal_gen.go is stale for the pinned contract; run this test with -update")
	}
}
