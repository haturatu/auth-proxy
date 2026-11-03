package logging

import (
    "net/http/httptest"
    "testing"
)

func TestClientIPVLANAndTrustedProxy(t *testing.T) {
    t.Cleanup(func(){ _ = ConfigureTrustedProxies("") })
    if err:=ConfigureTrustedProxies("");err!=nil { t.Fatal(err) }
    direct:=httptest.NewRequest("GET","http://192.168.10.5:8080/",nil)
    direct.RemoteAddr="192.168.20.10:4567"
    direct.Header.Set("X-Forwarded-For","1.2.3.4")
    if got:=GetClientIP(direct);got!="192.168.20.10" { t.Fatalf("direct VLAN IP spoofed: %s",got) }

    if err:=ConfigureTrustedProxies("192.168.10.5/32");err!=nil { t.Fatal(err) }
    reverse:=httptest.NewRequest("GET","http://auth.home/",nil)
    reverse.RemoteAddr="192.168.10.5:5432"
    reverse.Header.Set("X-Forwarded-For","1.2.3.4, 192.168.20.10")
    reverse.Header.Set("X-Forwarded-Proto","https")
    if got:=GetClientIP(reverse);got!="192.168.20.10" { t.Fatalf("trusted proxy IP: %s",got) }
    if got:=GetClientScheme(reverse);got!="https" { t.Fatalf("trusted proto: %s",got) }
}
