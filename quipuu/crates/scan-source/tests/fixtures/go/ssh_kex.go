// Fixture: golang.org/x/crypto/ssh Config.KeyExchanges lists, classical and
// migrated. RFC 10042 (August 2026, Informational) registers three hybrid
// ML-KEM SSH key-exchange identifiers; OpenSSH has shipped
// mlkem768x25519-sha256 as its default KEX since 10.0. Config.KeyExchanges
// is a plain []string (unlike tls.Config.CurvePreferences's typed
// []tls.CurveID), so a caller can name the group either via the package
// constant or the raw wire identifier — both forms appear below.

package fixtures

import "golang.org/x/crypto/ssh"

func migratedServer() *ssh.ServerConfig {
	return &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: []string{
				ssh.KeyExchangeMLKEM768X25519,
				"mlkem768nistp256-sha256",
				"mlkem1024nistp384-sha384",
			},
		},
	}
}

func classicalOnlyClient() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		Config: ssh.Config{
			KeyExchanges: []string{
				ssh.KeyExchangeCurve25519,
				ssh.KeyExchangeECDHP256,
				ssh.KeyExchangeECDHP384,
				ssh.KeyExchangeECDHP521,
			},
		},
	}
}
