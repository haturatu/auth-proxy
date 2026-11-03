package config

import "testing"

func TestProtectionDefaultsFailClosed(t *testing.T) {
	t.Setenv("PROTECT_FRONTEND", "")
	t.Setenv("PROTECT_API", "")
	// SetEnv("") is an explicit invalid boolean, which should use the
	// protected fallback instead of silently disabling protection.
	Init()
	if !Paths.ProtectFrontend || !Paths.ProtectAPI {
		t.Fatalf("default config must protect both planes: %+v", Paths)
	}
	t.Setenv("PROTECT_FRONTEND", "false")
	t.Setenv("PROTECT_API", "false")
	Init()
	if Paths.ProtectFrontend || Paths.ProtectAPI {
		t.Fatal("explicitly configured opt-out not honored")
	}
}
