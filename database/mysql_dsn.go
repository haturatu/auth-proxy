package database

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	mysql "github.com/go-sql-driver/mysql"
)

// mysqlDSN converts a standard mysql:// URL to the driver's DSN format.
// URL userinfo is decoded by net/url; FormatDSN handles DSN escaping.
func mysqlDSN(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse mysql URL: %w", err)
	}
	if u.Scheme != "mysql" || u.Hostname() == "" || u.User == nil || strings.TrimPrefix(u.Path, "/") == "" {
		return "", fmt.Errorf("mysql URL requires a host, username and database name")
	}
	port := u.Port()
	if port == "" {
		port = "3306"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid MySQL port")
	}
	cfg := mysql.NewConfig()
	cfg.User = u.User.Username()
	cfg.Passwd, _ = u.User.Password()
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(u.Hostname(), port)
	cfg.DBName = strings.TrimPrefix(u.Path, "/")
	cfg.ParseTime = true
	cfg.Params = make(map[string]string)

	for key, values := range u.Query() {
		value := values[len(values)-1]
		switch key {
		case "parseTime":
			if value != "true" {
				return "", fmt.Errorf("MySQL requires parseTime=true")
			}
		case "tls":
			cfg.TLSConfig = value
		case "loc":
			loc, err := time.LoadLocation(value)
			if err != nil {
				return "", fmt.Errorf("invalid MySQL loc: %w", err)
			}
			cfg.Loc = loc
		case "collation":
			cfg.Collation = value
		case "timeout":
			duration, err := time.ParseDuration(value)
			if err != nil {
				return "", fmt.Errorf("invalid MySQL timeout: %w", err)
			}
			cfg.Timeout = duration
		case "readTimeout":
			duration, err := time.ParseDuration(value)
			if err != nil {
				return "", fmt.Errorf("invalid MySQL readTimeout: %w", err)
			}
			cfg.ReadTimeout = duration
		case "writeTimeout":
			duration, err := time.ParseDuration(value)
			if err != nil {
				return "", fmt.Errorf("invalid MySQL writeTimeout: %w", err)
			}
			cfg.WriteTimeout = duration
		default:
			cfg.Params[key] = value
		}
	}
	return cfg.FormatDSN(), nil
}
