package gateway

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCreateRequestDeadlineRoundTripAndLimits(t *testing.T) {
	request := validClientCreateRequest("session-1", "target-1", 3306)
	deadline := time.Now().UTC().Add(time.Minute)
	request.ExpiresAt = &deadline
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CreateSessionRequest
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !SameCreateRequest(request, decoded) {
		t.Fatal("JSON round trip changed the approved identity")
	}
	changed := deadline.Add(time.Second)
	decoded.ExpiresAt = &changed
	if SameCreateRequest(request, decoded) {
		t.Fatal("changed deadline was treated as the same approval")
	}
	request.TTLSeconds = 18000
	if err := ValidateCreateRequest(request); err != nil {
		t.Fatal(err)
	}
	request.TTLSeconds++
	if err := ValidateCreateRequest(request); err == nil {
		t.Fatal("duration beyond five hours accepted")
	}
}
