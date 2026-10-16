package tables

import "testing"

func call() error { return nil }

func TestAMapOfClosuresWithoutRunIsFlagged(t *testing.T) {
	for name, f := range map[string]func() error{"a": call} { // want `each case of this table must run as a named t.Run with fresh state`
		if err := f(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestASliceOfCasesHoldingAFuncWithoutRunIsFlagged(t *testing.T) {
	for _, tc := range []struct { // want `each case of this table must run as a named t.Run with fresh state`
		name string
		call func() error
	}{{"a", call}} {
		_ = tc.call()
	}
}

func TestAMapOfClosuresWithRunPasses(t *testing.T) {
	for name, f := range map[string]func() error{"a": call} {
		t.Run(name, func(t *testing.T) {
			if err := f(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestATableOfValuesWithoutFuncsPasses(t *testing.T) {
	for _, n := range []int{1, 2} {
		if n == 0 {
			t.Fatal("zero")
		}
	}
}

func notATest() {
	for _, f := range []func() error{call} {
		_ = f()
	}
}

func TestAnArrayOfClosuresWithoutRunIsFlagged(t *testing.T) {
	for _, f := range [1]func() error{call} { // want `each case of this table must run as a named t.Run with fresh state`
		_ = f()
	}
}

func TestRangingOverANumberOrAStringPasses(t *testing.T) {
	for range 3 {
	}
	for range "abc" {
	}
}
