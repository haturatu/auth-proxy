package handlers

import (
	"testing"
)

func TestAdminUserIDStrictParsing(t *testing.T) {
	for _, tc := range []struct {
		path string
		suffix string
		valid bool
	}{
		{"/api/admin/users/17/role", "/role", true},
		{"/api/admin/users/17/status", "/status", true},
		{"/api/admin/users/17", "", true},
		{"/api/admin/users/17/x/role", "/role", false},
		{"/api/admin/users/17/role/", "/role", false},
		{"/api/admin/users/-1/role", "/role", false},
		{"/api/admin/users/0/role", "/role", false},
		{"/api/admin/users/17/extra", "", false},
		{"/api/admin/users/9999999999999999999999999", "", false},
	} {
		_, err := parseAdminUserID(tc.path, "/api/admin/users", tc.suffix)
		if (err == nil) != tc.valid {
			t.Errorf("%q suffix=%q accepted=%v, want valid=%v", tc.path, tc.suffix, err == nil, tc.valid)
		}
	}
}
