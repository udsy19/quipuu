// Fixture: `"none"` as the ordinary English word, in the shapes that produced
// 91 of the 92 CRYPTO-740 findings on the benchmark corpus.
//
// Nothing here is a JOSE registry, nothing here disables signature
// verification, and none of it may produce a finding.

package fixture

type EndpointType string
type IpcMode string

// AWS SDK shape: a generated enum whose zero value is spelled "none".
const (
	EndpointTypeAuto EndpointType = "auto"
	EndpointTypeNone EndpointType = "none"
)

// x-crypto/ssh shape: the null compression algorithm, in a const block of
// SSH protocol strings.
const (
	compressionNone = "none"
	serviceUserAuth = "ssh-userauth"
)

// Postgres shape: a connection-string value.
var requireAuth = "none"

// A switch on something that is not an algorithm at all.
func ipcMode(m IpcMode) string {
	switch string(m) {
	case "host":
		return "host"
	case "none":
		return "none"
	}
	return ""
}
