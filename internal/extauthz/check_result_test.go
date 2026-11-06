package extauthz

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/extauthz/internal/clientdata"
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
				// After a merge the winning (more-restrictive) result's fields replace r1's,
				// except withXFCCHeader which uses OR semantics.
				assert.Equal(t, r2copy.is, tc.r1.is)
				assert.Equal(t, r2copy.info, tc.r1.info)
				assert.Equal(t, r2copy.subject, tc.r1.subject)
				assert.Equal(t, r2copy.givenname, tc.r1.givenname)
				assert.Equal(t, r2copy.familyname, tc.r1.familyname)
				assert.Equal(t, r2copy.email, tc.r1.email)
				assert.Equal(t, r2copy.region, tc.r1.region)
				assert.Equal(t, r2copy.groups, tc.r1.groups)
				assert.Equal(t, r2copy.authContext, tc.r1.authContext)
				assert.Equal(t, r2copy.kind, tc.r1.kind)
				assert.Equal(t, r2copy.clientTypeOverride, tc.r1.clientTypeOverride)
				// OR semantics: true on either side survives
				assert.Equal(t, r1copy.withXFCCHeader || r2copy.withXFCCHeader, tc.r1.withXFCCHeader)
			} else {
				// without a merge, r1 should stay the same
				assert.Equal(t, r1copy, tc.r1)
			}
		})
	}

	// withXFCCHeader uses OR semantics: a true flag on the losing side must not
	// be cleared when the more-restrictive result wins the merge.
	t.Run("withXFCCHeader is ORed across results", func(t *testing.T) {
		r1 := checkResult{is: ALLOWED, withXFCCHeader: true, kind: authKindX509}
		r2 := checkResult{is: DENIED, withXFCCHeader: false, kind: authKindJWT}
		r1.merge(r2)
		assert.Equal(t, DENIED, r1.is)
		assert.True(t, r1.withXFCCHeader, "XFCC flag must survive when more-restrictive result wins")
	})

	// clientTypeOverride uses replace semantics: the winning (more-restrictive) result's
	// value is kept. It is only consumed when the final merged result is ALLOWED, so
	// replacing with nil on a DENIED merge is intentional and harmless.
	t.Run("clientTypeOverride is taken from more-restrictive result", func(t *testing.T) {
		tu := clientdata.TechnicalUser
		// DENIED wins over ALLOWED: clientTypeOverride is replaced with nil (DENIED result
		// ignores clientTypeOverride because toClientDataOptions is only called on ALLOWED).
		r1 := checkResult{is: ALLOWED, clientTypeOverride: &tu}
		r2 := checkResult{is: DENIED, clientTypeOverride: nil}
		r1.merge(r2)
		assert.Equal(t, DENIED, r1.is)
		assert.Nil(t, r1.clientTypeOverride, "DENIED result replaces clientTypeOverride with nil")
	})

	t.Run("clientTypeOverride is preserved when less-restrictive result loses", func(t *testing.T) {
		tu := clientdata.TechnicalUser
		// ALLOWED does not win over another ALLOWED (equal restrictiveness = no merge);
		// verify with ALLOWED vs UNKNOWN so the JWT ALLOWED is more restrictive.
		r1 := checkResult{is: UNKNOWN, clientTypeOverride: nil}
		r2 := checkResult{is: ALLOWED, clientTypeOverride: &tu}
		r1.merge(r2)
		assert.Equal(t, ALLOWED, r1.is)
		assert.Equal(t, &tu, r1.clientTypeOverride, "winning ALLOWED result's clientTypeOverride is adopted")
	})

	t.Run("clientTypeOverride is adopted from equal-restrictiveness result", func(t *testing.T) {
		tu := clientdata.TechnicalUser
		// Scenario: XFCC produces ALLOWED first (withXFCCHeader=true, no override),
		// then JWT produces ALLOWED with a clientTypeOverride. The two results are
		// equal-restrictiveness so the identity fields are NOT replaced, but the
		// explicit clientTypeOverride from the JWT path-prefix rule must still be adopted.
		r1 := checkResult{is: ALLOWED, withXFCCHeader: true, clientTypeOverride: nil}
		r2 := checkResult{is: ALLOWED, clientTypeOverride: &tu}
		r1.merge(r2)
		assert.Equal(t, ALLOWED, r1.is)
		assert.True(t, r1.withXFCCHeader, "withXFCCHeader must survive")
		assert.Equal(t, &tu, r1.clientTypeOverride, "JWT explicit clientTypeOverride must win over nil XFCC override on equal result")
	})
}
