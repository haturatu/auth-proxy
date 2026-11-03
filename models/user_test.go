package models

import (
    "strings"
    "testing"
)

func TestPBKDF2OptionalAndBcryptCompatible(t *testing.T) {
    t.Setenv("PASSWORD_HASH_ALGORITHM","bcrypt")
    existing,err:=HashPassword("correct horse battery staple")
    if err!=nil {t.Fatal(err)}
    t.Setenv("PASSWORD_HASH_ALGORITHM","pbkdf2-sha256")
    newer,err:=HashPassword("correct horse battery staple")
    if err!=nil {t.Fatal(err)}
    if !strings.HasPrefix(newer,"$pbkdf2-sha256$") {t.Fatal("missing algorithm identifier")}
    for _,hash:=range []string{existing,newer} {
        if !CheckPasswordHash("correct horse battery staple",hash) {t.Fatal("valid password rejected")}
        if CheckPasswordHash("invalid",hash) {t.Fatal("invalid password accepted")}
    }
}
