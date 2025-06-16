package testutils_test

import (
	"reflect"
	"testing"

	"github.com/openkcm/extauthz/internal/testutils"
)

type TestStruct struct {
	Field1 string
	Field2 int
}

func TestNewMutator(t *testing.T) {
	// Arrange
	baseProv := func() TestStruct {
		return TestStruct{
			Field1: "initial",
			Field2: 42,
		}
	}
	mutator := testutils.NewMutator(baseProv)

	// create the test cases
	tests := []struct {
		name      string
		mutatorFn func(*TestStruct)
		want      TestStruct
	}{
		{
			name:      "No mutation",
			mutatorFn: func(_ *TestStruct) {},
			want: TestStruct{
				Field1: "initial",
				Field2: 42,
			},
		},
		{
			name: "Mutate Field1",
			mutatorFn: func(ts *TestStruct) {
				ts.Field1 = "mutated"
			},
			want: TestStruct{
				Field1: "mutated",
				Field2: 42,
			},
		},
		{
			name: "Mutate Field2",
			mutatorFn: func(ts *TestStruct) {
				ts.Field2 = 100
			},
			want: TestStruct{
				Field1: "initial",
				Field2: 100,
			},
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act
			got := mutator(tc.mutatorFn)

			// Assert
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("expected: %+v, got: %+v", tc.want, got)
			}
		})
	}
}
