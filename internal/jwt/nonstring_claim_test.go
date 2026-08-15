package jwt

import (
	"encoding/json"
	"testing"
)

// TestNonStringStandardClaimPreservedInExtra verifies that when a standard claim
// (iss, sub, aud, jti) has a non-string JSON value (array, number, etc.),
// the value is preserved in Extra rather than silently dropped.
func TestNonStringStandardClaimPreservedInExtra(t *testing.T) {
	// aud as array (RFC 7519 allows string or array of strings)
	data := []byte(`{"sub":"alice","aud":["svc-1","svc-2"],"jti":12345}`)
	var c Claims
	err := json.Unmarshal(data, &c)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// aud array cannot be stored in Audience (string field),
	// so it must be preserved in Extra["aud"]
	if c.Extra["aud"] == nil {
		t.Fatalf("aud array was silently dropped; expected it in Extra[\"aud\"]")
	}
	audSlice, ok := c.Extra["aud"].([]any)
	if !ok {
		t.Fatalf("Extra[\"aud\"] should be []any, got %T", c.Extra["aud"])
	}
	if len(audSlice) != 2 || audSlice[0] != "svc-1" || audSlice[1] != "svc-2" {
		t.Fatalf("aud content mismatch: %v", audSlice)
	}

	// jti as number cannot be stored in ID (string field),
	// so it must be preserved in Extra["jti"]
	if c.Extra["jti"] == nil {
		t.Fatalf("numeric jti was silently dropped; expected it in Extra[\"jti\"]")
	}
	if c.Extra["jti"] != float64(12345) {
		t.Fatalf("Extra[\"jti\"] content mismatch: %v", c.Extra["jti"])
	}
}
