// Fixture for Phase 16 (SiteContext) FP suppression.
//
// The Phase 14a precision audit surfaced 8 FP patterns where the scanner
// matched a JOSE algorithm string in a non-operational position. Phase 16
// classifies each match by syntactic context (MapEntry, TestAssertion,
// StructLiteral, Call, StringConstant, Default) at extract time, and rules
// opt in via `when.site_context`.
//
// Lines marked NO_FIRE must NOT produce a finding.
// Lines marked FIRE must produce the expected CRYPTO-NNN rule.

package fixture

import "testing"

// ── Operational TPs — must FIRE ────────────────────────────────────────

// StructLiteral: golang-jwt-jwt's algorithm registration.
type SigningMethodRSA struct {
	Name string
}

var SigningMethodRS256_TP = &SigningMethodRSA{"RS256"} // FIRE CRYPTO-700

// StringConstant: const declaration is the algorithm-registration site.
const HS256_CONST = "HS256" // FIRE CRYPTO-730

// Call: switch dispatch on the algorithm.
func dispatch(alg string) {
	switch alg {
	case "RS256": // FIRE CRYPTO-700
		_ = alg
	case "PS384": // FIRE CRYPTO-704
		_ = alg
	}
}

// ── Non-operational FPs — must NOT fire ────────────────────────────────

// Pattern F (#66, #68): parser-config slice literal — algorithm strings
// are configuration data, not crypto operations.
var ValidMethods_FP = []string{"RS256", "HS256", "ES256"} // NO_FIRE

// Pattern I (#14): allowlist map entry.
var AllowedAlgs_FP = map[string]bool{
	"RS512": true,  // NO_FIRE (CRYPTO-702)
	"PS384": false, // NO_FIRE (CRYPTO-704)
}

// Pattern F (#70): test-framework assertion.
func TestStringification_FP(t *testing.T) {
	require.Equal(t, "HS256", "HS256") // NO_FIRE (CRYPTO-730)
	require.NotEqual(t, "RS512", "")   // NO_FIRE (CRYPTO-702)
}

// Pattern F (#75): slice passed to a function (test or otherwise).
func ConfigureParser_FP() {
	jwt.NewParser(jwt.WithValidMethods([]string{"HS256", "ES256"})) // NO_FIRE
}
