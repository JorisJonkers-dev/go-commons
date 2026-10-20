package principalgen_test

import (
	"io/fs"
	"strings"
	"testing"

	contract "github.com/JorisJonkers-dev/identity/contract/principal"

	"github.com/JorisJonkers-dev/go-commons/internal/principalgen"
)

func generated(t *testing.T, schema string) string {
	t.Helper()
	out, err := principalgen.Generate("p", []byte(schema))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestThePinnedSchemaGeneratesAPrincipalWithEveryContractField(t *testing.T) {
	raw, err := fs.ReadFile(contract.Files, "principal.schema.json")
	if err != nil {
		t.Fatal(err)
	}

	out := generated(t, string(raw))

	for _, field := range []string{
		"Subject string `json:\"subject\"`", "Kind Kind `json:\"kind\"`", "Email string `json:\"email,omitempty\"`",
		"Roles []string `json:\"roles\"`", "Actor *Actor `json:\"actor,omitempty\"`", "TwoFactor bool `json:\"twoFactor\"`",
		"TwoFactorAt *time.Time `json:\"twoFactorAt,omitempty\"`", "SID string `json:\"sid,omitempty\"`", "ViaPersonalToken Via = \"personal-token\"",
	} {
		if !strings.Contains(strings.Join(strings.Fields(out), " "), field) {
			t.Errorf("no %s in\n%s", field, out)
		}
	}
}

func TestARequiredDateTimeAndObjectAreValuesNotPointers(t *testing.T) {
	out := generated(t, `{"title": "T", "type": "object", "required": ["at", "who"], "properties": {
		"at": {"type": "string", "format": "date-time"},
		"who": {"type": "object", "properties": {"id": {"type": "string"}}}}}`)

	if !strings.Contains(out, "At  time.Time") || !strings.Contains(out, "Who Who") {
		t.Fatalf("generated\n%s", out)
	}
}

func TestATypeWithoutTimesImportsNothing(t *testing.T) {
	if out := generated(t, `{"title": "T", "type": "object", "properties": {"a": {"type": "boolean"}}}`); strings.Contains(out, "import") {
		t.Fatalf("generated\n%s", out)
	}
}

func TestADescriptionIsWrappedIntoTheDocComment(t *testing.T) {
	out := generated(t, `{"title": "T", "type": "object", "properties": {"a": {"type": "boolean",
		"description": "Whether a very long description, which runs well past the width of one line of a doc comment, wraps onto a second line."}}}`)

	if !strings.Contains(out, "// A is whether a very long description") || !strings.Contains(out, "\n\t// comment, wraps onto a second line.") {
		t.Fatalf("generated\n%s", out)
	}
}

func TestAShapeTheGeneratorDoesNotKnowIsAnError(t *testing.T) {
	for _, c := range []struct{ name, schema string }{
		{"a number", `{"title": "T", "type": "object", "properties": {"n": {"type": "number"}}}`},
		{"an array of objects", `{"title": "T", "type": "object", "properties": {"a": {"type": "array", "items": {"type": "object"}}}}`},
		{"a nested object with a number", `{"title": "T", "type": "object", "properties": {"o": {"type": "object", "properties": {"n": {"type": "number"}}}}}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := principalgen.Generate("p", []byte(c.schema)); err == nil {
				t.Fatal("generated a type for it")
			}
		})
	}
}

func TestASchemaThatIsNoJSONIsAnError(t *testing.T) {
	for _, c := range []struct{ name, schema string }{
		{"not JSON", `{`},
		{"properties that are no object", `{"title": "T", "properties": 3}`},
		{"a property that is no schema", `{"title": "T", "properties": {"a": 3}}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := principalgen.Generate("p", []byte(c.schema)); err == nil {
				t.Fatal("generated a type from it")
			}
		})
	}
}
