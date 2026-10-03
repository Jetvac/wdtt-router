package controller

import (
	"strings"
	"testing"
)

func TestRedactError(t *testing.T) {
	message := "failed vless://user:password@host:24443?security=none token=cfut_exampleSecret password=guess Bearer abc.def.ghi"
	redacted := redactError(message)
	for _, secret := range []string{"vless://", "exampleSecret", "guess", "abc.def.ghi"} {
		if strings.Contains(redacted, secret) {
			t.Errorf("redacted error contains %q: %s", secret, redacted)
		}
	}
	if !strings.Contains(redacted, "failed") {
		t.Errorf("redacted error lost context: %s", redacted)
	}
}
