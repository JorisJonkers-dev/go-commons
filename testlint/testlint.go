// Package testlint holds analyzers for the estate testing standards: a test is named as the
// behaviour it checks, and a table of cases runs each case as a named t.Run with fresh state
// (workspace docs/testing-standards.md, sections 2 and 3).
package testlint

import (
	"go/ast"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// TestName reports a test whose name, after Test, has one or two words: TestMembers says nothing
// about what it checks.
func TestName() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name: "testname",
		Doc:  "report test names of one or two words; a test is named as the behaviour it checks",
		Run:  runTestName,
	}
}

// ClosureTable reports a loop in a test over functions, or over cases holding one, whose body
// never calls t.Run: one case cannot be run on its own, and the cases share one fixture.
func ClosureTable() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name: "closuretable",
		Doc:  "report tables of functions in tests that do not run each case as a named t.Run",
		Run:  runClosureTable,
	}
}

func testFuncs(pass *analysis.Pass) []*ast.FuncDecl {
	var out []*ast.FuncDecl
	for _, file := range pass.Files {
		if !strings.HasSuffix(pass.Fset.File(file.Pos()).Name(), "_test.go") {
			continue
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && takesT(fn) {
				out = append(out, fn)
			}
		}
	}
	return out
}

// takesT reports whether a function is a test: TestXxx(t *testing.T).
func takesT(fn *ast.FuncDecl) bool {
	if !strings.HasPrefix(fn.Name.Name, "Test") || fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
		return false
	}
	star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "T"
}

func runTestName(pass *analysis.Pass) (any, error) {
	word := regexp.MustCompile(`[A-Z][a-z0-9]*`) // the words of a test name, as CamelCase splits it
	for _, fn := range testFuncs(pass) {
		if len(word.FindAllString(strings.TrimPrefix(fn.Name.Name, "Test"), -1)) <= 2 {
			pass.Reportf(fn.Name.Pos(), "test name %s names no behaviour: write the behaviour as a sentence", fn.Name.Name)
		}
	}
	return nil, nil //nolint:nilnil // an analyzer with no result for others returns nothing
}

func runClosureTable(pass *analysis.Pass) (any, error) {
	for _, fn := range testFuncs(pass) {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			loop, ok := n.(*ast.RangeStmt)
			if ok && holdsFuncs(pass.TypesInfo.TypeOf(loop.X)) && !callsRun(loop.Body) {
				pass.Reportf(loop.Pos(), "each case of this table must run as a named t.Run with fresh state")
			}
			return true
		})
	}
	return nil, nil //nolint:nilnil // an analyzer with no result for others returns nothing
}

// holdsFuncs reports whether ranging over t yields functions, or structs carrying one.
func holdsFuncs(t types.Type) bool {
	var elem types.Type
	switch c := t.Underlying().(type) {
	case *types.Map:
		elem = c.Elem()
	case *types.Slice:
		elem = c.Elem()
	case *types.Array:
		elem = c.Elem()
	default:
		return false
	}
	switch e := elem.Underlying().(type) {
	case *types.Signature:
		return true
	case *types.Struct:
		for i := range e.NumFields() {
			if _, ok := e.Field(i).Type().Underlying().(*types.Signature); ok {
				return true
			}
		}
	}
	return false
}

// callsRun reports whether a loop body calls Run, as t.Run(name, ...) does.
func callsRun(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Run" {
				found = true
			}
		}
		return !found
	})
	return found
}
