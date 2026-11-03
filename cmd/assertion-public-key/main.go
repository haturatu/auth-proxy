package main

import (
	"auth-proxy/utils"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	public, err := utils.UpstreamAssertionPublicKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid upstream assertion seed:", err)
		os.Exit(1)
	}
	if len(public) == 0 {
		fmt.Fprintln(os.Stderr, "UPSTREAM_ASSERTION_ED25519_SEED is not configured")
		os.Exit(1)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(public))
}
