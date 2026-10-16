package names

import "testing"

func TestMembers(t *testing.T) {} // want `test name TestMembers names no behaviour: write the behaviour as a sentence`

func TestAddMember(t *testing.T) {} // want `test name TestAddMember names no behaviour: write the behaviour as a sentence`

func TestAnAdminAddsAPersonToAGroup(t *testing.T) {}

func TestTheLastAdminCannotLeave(t *testing.T) {}

func TestMain(m *testing.M) {}

func BenchmarkMembers(b *testing.B) {}

func helperMembers(t *testing.T) {}

func Testify(n int) {}
