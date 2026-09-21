package operationaudit

import "testing"

func TestNormalizeAssetProtocols(t *testing.T) {
	for _, sample := range []struct{ input, want string }{
		{"mysql", ProtocolMySQL}, {"postgres", ProtocolPostgreSQL}, {"PostgreSQL", ProtocolPostgreSQL},
		{"redis", ProtocolRedis}, {"mongo", ProtocolMongoDB}, {"mongodb", ProtocolMongoDB},
		{"https", ProtocolHTTP}, {"http", ProtocolHTTP}, {"sshd", ProtocolSSH}, {"ssh", ProtocolSSH},
	} {
		if got := NormalizeProtocol(sample.input); got != sample.want || !ValidAssetProtocol(sample.input) {
			t.Fatalf("normalize %q = %q, valid=%v; want %q", sample.input, got, ValidAssetProtocol(sample.input), sample.want)
		}
	}
	if ValidAssetProtocol("aws_ecs") {
		t.Fatal("cloud provider asset type was treated as an application protocol")
	}
}
