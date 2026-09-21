package cloudassets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
func reply(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

var testCredentials = Credentials{AccessKey: "unit-test-ak", SecretKey: "unit-test-sk"}

func TestAWSDiscoveryUsesSDKSigningAndPrivateAddresses(t *testing.T) {
	calls := 0
	client := NewClient()
	client.http.Transport = transportFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Scheme != "https" || request.URL.Host != "ec2.us-east-1.amazonaws.com" || !strings.Contains(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			t.Fatal("AWS request was not signed over HTTPS")
		}
		body, _ := io.ReadAll(request.Body)
		query, _ := url.ParseQuery(string(body))
		if query.Get("Action") != "DescribeInstances" || query.Get("MaxResults") != "1000" {
			t.Fatal("unexpected AWS operation")
		}
		token := "<nextToken>page-two</nextToken>"
		if calls == 2 {
			if query.Get("NextToken") != "page-two" {
				t.Fatal("AWS pagination token missing")
			}
			token = ""
		}
		return reply(fmt.Sprintf(`<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item><instancesSet><item><instanceId>i-%d</instanceId><privateIpAddress>10.0.0.%d</privateIpAddress><ipAddress>203.0.113.10</ipAddress><tagSet><item><key>Name</key><value>database</value></item></tagSet></item></instancesSet></item></reservationSet>%s</DescribeInstancesResponse>`, calls, calls, token)), nil
	})
	values, err := client.Discover(context.Background(), "aws", testCredentials, "us-east-1", nil)
	if err != nil || len(values) != 2 || calls != 2 || values[0].Host != "10.0.0.1" || values[0].Name != "database" {
		t.Fatalf("discovery: %+v, %v", values, err)
	}
}

func TestAWSInstanceSelectionUsesFiltersForMissingIDs(t *testing.T) {
	client := NewClient()
	client.http.Transport = transportFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		query, _ := url.ParseQuery(string(body))
		if query.Get("Filter.1.Name") != "instance-id" || query.Get("Filter.1.Value.1") != "i-selected" || query.Get("Filter.1.Value.2") != "i-missing" || query.Has("InstanceId.1") {
			t.Fatal("invalid AWS targeted request")
		}
		return reply(`<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-selected</instanceId><privateIpAddress>10.0.0.1</privateIpAddress></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`), nil
	})
	values, err := client.Discover(context.Background(), "aws", testCredentials, "cn-north-1", []string{"i-selected", "i-missing"})
	if err != nil || len(values) != 1 {
		t.Fatalf("targeted: %+v, %v", values, err)
	}
}

func TestAliyunDiscoveryUsesRegionalSDKEndpointAndPagination(t *testing.T) {
	client := NewClient()
	calls := 0
	client.http.Transport = transportFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Scheme != "https" || request.URL.Host != "ecs-cn-hangzhou.aliyuncs.com" {
			t.Fatal("incorrect Aliyun endpoint")
		}
		query := request.URL.Query()
		action := ""
		for name, values := range request.Header {
			if strings.EqualFold(name, "x-acs-action") {
				action = values[0]
			}
		}
		if action != "DescribeInstances" || query.Get("MaxResults") != "100" {
			t.Fatal("invalid Aliyun query")
		}
		if query.Get("Signature") == "" && request.Header.Get("Authorization") == "" {
			t.Fatal("unsigned Aliyun request")
		}
		if calls == 1 {
			return reply(`{"Instances":{"Instance":[{"InstanceId":"i-first","InstanceName":"mysql","VpcAttributes":{"PrivateIpAddress":{"IpAddress":["10.2.0.8"]}}}]},"NextToken":"second"}`), nil
		}
		if query.Get("NextToken") != "second" {
			t.Fatal("missing Aliyun next token")
		}
		return reply(`{"Instances":{"Instance":[{"InstanceId":"i-second","InnerIpAddress":{"IpAddress":["10.2.0.9"]}}]}}`), nil
	})
	values, err := client.Discover(context.Background(), "aliyun", testCredentials, "cn-hangzhou", nil)
	if err != nil || len(values) != 2 || values[0].Host != "10.2.0.8" || values[1].Host != "10.2.0.9" {
		t.Fatalf("Aliyun: %+v, %v", values, err)
	}
}

func TestAliyunTargetedDiscoveryAndCancellation(t *testing.T) {
	client := NewClient()
	ctx, cancel := context.WithCancel(context.Background())
	client.http.Transport = transportFunc(func(request *http.Request) (*http.Response, error) {
		query := request.URL.Query()
		var ids []string
		if json.Unmarshal([]byte(query.Get("InstanceIds")), &ids) != nil || len(ids) != 1 || ids[0] != "i-1" || query.Has("MaxResults") {
			t.Fatal("invalid Aliyun ID filter")
		}
		cancel()
		if request.Context().Err() == nil {
			t.Fatal("SDK HTTP hook did not propagate cancellation")
		}
		return nil, request.Context().Err()
	})
	values, err := client.Discover(ctx, "aliyun", testCredentials, "cn-hangzhou", []string{"i-1"})
	if err == nil || values != nil {
		t.Fatal("cancelled discovery returned a snapshot")
	}
}

func TestHuaweiResolvesRegionProjectAndPaginates(t *testing.T) {
	client := NewClient()
	calls := 0
	client.http.Transport = transportFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Scheme != "https" || !strings.HasPrefix(request.Header.Get("Authorization"), "SDK-HMAC-SHA256 ") {
			t.Fatal("unsigned Huawei request")
		}
		if calls == 1 {
			if request.URL.Query().Get("name") != "cn-north-4" {
				t.Fatal("project lookup ignored region")
			}
			return reply(`{"projects":[{"id":"wrong","name":"cn-north-4-other","enabled":true},{"id":"project-1","name":"cn-north-4","enabled":true}]}`), nil
		}
		if request.URL.Host != "ecs.cn-north-4.myhuaweicloud.com" || request.URL.Path != "/v1/project-1/cloudservers/detail" {
			t.Fatal("wrong project or endpoint")
		}
		if calls == 2 {
			if request.URL.Query().Get("offset") != "0" {
				t.Fatal("first offset skipped records")
			}
			servers := make([]map[string]any, 1000)
			for i := range servers {
				servers[i] = map[string]any{"id": fmt.Sprintf("host-%d", i), "addresses": map[string]any{"vpc": []map[string]string{{"addr": "10.0.0.8", "OS-EXT-IPS:type": "fixed"}}}}
			}
			body, _ := json.Marshal(map[string]any{"count": 1001, "servers": servers})
			return reply(string(body)), nil
		}
		if request.URL.Query().Get("offset") != "1000" {
			t.Fatal("Huawei offset used page number")
		}
		return reply(`{"count":1001,"servers":[{"id":"last","name":"last server","addresses":{"vpc":[{"addr":"203.0.113.3","OS-EXT-IPS:type":"floating"},{"addr":"10.0.0.9","OS-EXT-IPS:type":"fixed"}]}}]}`), nil
	})
	values, err := client.Discover(context.Background(), "huaweicloud", testCredentials, "cn-north-4", []string{"last"})
	if err != nil || len(values) != 1 || values[0].Host != "10.0.0.9" || calls != 3 {
		t.Fatalf("Huawei: %+v, %v", values, err)
	}
}

func TestDiscoveryRejectsUntrustedScopeAndIncompleteSnapshots(t *testing.T) {
	client := NewClient()
	calls := 0
	client.http.Transport = transportFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return reply(`{"Instances":{"Instance":[]},"NextToken":"repeated"}`), nil
	})
	for _, region := range []string{"", "../../local", "cn-hangzhou.attacker.test", "cn-hangzhou:443", "cn-hangzhou/"} {
		if _, err := client.Discover(context.Background(), "aliyun", testCredentials, region, nil); err == nil {
			t.Fatal("invalid region accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid region caused a request")
	}
	values, err := client.Discover(context.Background(), "aliyun", testCredentials, "cn-hangzhou", nil)
	var failure *Error
	if values != nil || !errors.As(err, &failure) || failure.Code != "incomplete_pagination" || calls != 2 {
		t.Fatalf("repeated page accepted: %v", err)
	}
	client.http.Transport = transportFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("signed request " + testCredentials.AccessKey + " " + testCredentials.SecretKey)
	})
	_, err = client.Discover(context.Background(), "aws", testCredentials, "us-east-1", nil)
	if err == nil || strings.Contains(err.Error(), testCredentials.AccessKey) || strings.Contains(err.Error(), testCredentials.SecretKey) {
		t.Fatal("SDK error leaked credentials")
	}
}
