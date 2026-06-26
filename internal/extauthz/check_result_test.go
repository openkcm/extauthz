package extauthz

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/extauthz/internal/testutils"
)

func TestMerge(t *testing.T) {
	// Arrange
	r1mutator := testutils.NewMutator(func() checkResult {
		return checkResult{
			is:         ALLOWED,
			info:       "Info1",
			subject:    "Subject1",
			givenname:  "GivenName1",
			familyname: "FamilyName1",
			email:      "email1@foo.bar",
			region:     "Region1",
			groups:     []string{"Group1"},
			kind:       authKindX509,
		}
	})
	r2mutator := testutils.NewMutator(func() checkResult {
		return checkResult{
			is:         ALLOWED,
			info:       "Info2",
			subject:    "Subject2",
			givenname:  "GivenName2",
			familyname: "FamilyName2",
			email:      "email2@foo.bar",
			region:     "Region2",
			groups:     []string{"Group2"},
			kind:       authKindJWT,
		}
	})

	// create the test cases
	tests := []struct {
		name  string
		r1    checkResult
		r2    checkResult
		merge bool
	}{
		{
			name:  "merge as r2 is more restrictive",
			r1:    r1mutator(func(k *checkResult) { k.is = ALLOWED }),
			r2:    r2mutator(func(k *checkResult) { k.is = DENIED }),
			merge: true,
		}, {
			name:  "no merge as r2 is less restrictive",
			r1:    r1mutator(func(k *checkResult) { k.is = DENIED }),
			r2:    r2mutator(func(k *checkResult) { k.is = ALLOWED }),
			merge: false,
		}, {
			name:  "merge adopts other's kind when other is more restrictive",
			r1:    r1mutator(func(k *checkResult) { k.is = ALLOWED; k.kind = authKindX509 }),
			r2:    r2mutator(func(k *checkResult) { k.is = UNAUTHENTICATED; k.kind = authKindSession }),
			merge: true,
		}, {
			name:  "no merge keeps original kind when already most restrictive",
			r1:    r1mutator(func(k *checkResult) { k.is = UNAUTHENTICATED; k.kind = authKindX509 }),
			r2:    r2mutator(func(k *checkResult) { k.is = ALLOWED; k.kind = authKindSession }),
			merge: false,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			r1copy := tc.r1
			r2copy := tc.r2

			// Act
			tc.r1.merge(tc.r2)

			// Assert
			if tc.merge {
				// after a merge, r1 should equal r2
				assert.Equal(t, r2copy, tc.r1)
			} else {
				// without a merge, r1 should stay the same
				assert.Equal(t, r1copy, tc.r1)
			}
		})
	}
}
