package security

import (
	"encoding/hex"
	"testing"
)

// These pre-rename derivation values are persistent contracts: changing one
// would invalidate stored ciphertext, login signatures, or active agents.
func TestDeriveKeyPreservesExistingPurposes(t *testing.T) {
	for purpose, expected := range map[string]string{
		"asset-targets":       "466474c479acb9ffec48ba3e2b8973b9e1a08566d54b30dc3dea9eb7b93dbc11",
		"system-settings":     "6c7db8d49b1a6eb2695872ea359d555f7a2ff80d0e9cefcb9de39c8b6aa995d8",
		"session-agent-audit": "74ec8b9cc92f0d2d2cb0af7e8a362aec1999a7b465a083982bcd33e9b66eed0a",
		"browser-session":     "e3099961866525cb6130e35e956739afd2d919b4c2791ffdb9607c6bcee6c191",
		"cloud-assets":        "4ce4c21a3097119a75ab0df62456f0468c6067d848bca780230e6daa362e946b",
		"browser-transport":   "f6f5692deef04c9e4c0b5319c9f06d18175ab52839f02f66fc1eada68101a10c",
		"identity-security":   "5bf01a42b3363af80a1381194e2960651601894f8a6f8b96e427b3e571eca3aa",
		"session-tunnel":      "2262e88f41d87e2d6f368dc88c79b0f476a0f5ff18724747661efac67344a1c9",
	} {
		t.Run(purpose, func(t *testing.T) {
			if actual := hex.EncodeToString(DeriveKey("compatibility-test-encryption-key", purpose)); actual != expected {
				t.Fatal("renamed encryption configuration changed an existing derived key")
			}
		})
	}
}
