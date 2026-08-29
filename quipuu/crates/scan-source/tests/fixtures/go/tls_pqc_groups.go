// Fixture: a crypto/tls config that has already been migrated to the hybrid
// PQC key-agreement groups, plus the pre-standard Kyber draft group.
//
// Before CRYPTO-044..048 existed, this file produced findings only for its
// classical neighbours, so a migrated service was indistinguishable from an
// unscanned one.

package fixtures

import "crypto/tls"

func migratedServer() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.SecP256r1MLKEM768,
			tls.SecP384r1MLKEM1024,
			tls.MLKEM1024,
			tls.X25519,
		},
	}
}

func staleDraftClient() *tls.Config {
	return &tls.Config{
		CurvePreferences: []tls.CurveID{
			tls.X25519Kyber768Draft00,
		},
	}
}
