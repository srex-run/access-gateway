package id

import "testing"

func TestNewReturnsRFC4122Version4UUID(t *testing.T) {
	first := New()
	second := New()
	if !IsUUID(first) || !IsUUID(second) || first == second {
		t.Fatalf("generated UUIDs are invalid: %q %q", first, second)
	}
	if first[14] != '4' {
		t.Fatalf("UUID version nibble = %q", first[14])
	}
	if first[19] != '8' && first[19] != '9' && first[19] != 'a' && first[19] != 'b' {
		t.Fatalf("UUID variant nibble = %q", first[19])
	}
}

func TestIsUUIDRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{"", "not-a-uuid", "00000000-0000-0000-0000-00000000000z", "000000000000-0000-0000-000000000000"} {
		if IsUUID(value) {
			t.Fatalf("IsUUID(%q) = true", value)
		}
	}
}
