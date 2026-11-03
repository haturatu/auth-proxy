package database

import (
	"testing"

	mysql "github.com/go-sql-driver/mysql"
)

func TestMySQLDSN(t *testing.T) {
	dsn, err := mysqlDSN("mysql://auth:p%40ss%3Aword@mysql:3306/auth?charset=utf8mb4&parseTime=true&tls=true")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User != "auth" || cfg.Passwd != "p@ss:word" || cfg.Addr != "mysql:3306" || cfg.DBName != "auth" || !cfg.ParseTime || cfg.TLSConfig != "true" {
		t.Fatalf("unexpected MySQL config: user=%q addr=%q db=%q parseTime=%v tls=%q", cfg.User, cfg.Addr, cfg.DBName, cfg.ParseTime, cfg.TLSConfig)
	}
}

func TestMySQLDSNInvalid(t *testing.T) {
	for _, u := range []string{
		"mysql://auth:pw@mysql/auth?parseTime=false",
		"mysql://auth:pw@mysql:70000/auth",
		"mysql://auth:pw@mysql:3306",
		"mysql://auth:pw@mysql/auth?timeout=invalid",
	} {
		if _, err := mysqlDSN(u); err == nil {
			t.Errorf("mysqlDSN(%q) should fail", u)
		}
	}
}
