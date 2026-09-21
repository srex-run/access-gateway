package cloudassets

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ecs "github.com/alibabacloud-go/ecs-20140526/v7/client"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/alibabacloud-go/tea/tea"
)

// Tea's generated methods lack context parameters; bind context in its HTTP hook.
type aliyunHTTP struct {
	ctx    context.Context
	client *http.Client
}

func (c aliyunHTTP) Call(request *http.Request, _ *http.Transport) (*http.Response, error) {
	return c.client.Do(request.Clone(c.ctx))
}

func (c *Client) aliyun(ctx context.Context, credentials Credentials, region string, ids []string) ([]Instance, error) {
	client, err := ecs.NewClient(&openapi.Config{
		AccessKeyId: tea.String(credentials.AccessKey), AccessKeySecret: tea.String(credentials.SecretKey),
		SecurityToken: tea.String(credentials.SessionToken), RegionId: tea.String(region), Protocol: tea.String("https"),
	})
	if err != nil {
		return nil, apiError(err)
	}
	client.HttpClient = aliyunHTTP{ctx: ctx, client: c.http}
	request := &ecs.DescribeInstancesRequest{RegionId: tea.String(region)}
	if len(ids) > 0 {
		encoded, _ := json.Marshal(ids)
		request.InstanceIds = tea.String(string(encoded))
		request.PageNumber, request.PageSize = tea.Int32(1), tea.Int32(100)
	} else {
		request.MaxResults = tea.Int32(100)
	}
	var values []Instance
	seen := make(map[string]bool)
	for page := 0; page < 200; page++ {
		if err := ctx.Err(); err != nil {
			return nil, apiError(err)
		}
		response, err := client.DescribeInstancesWithOptions(request, &dara.RuntimeOptions{
			ConnectTimeout: tea.Int(20000), ReadTimeout: tea.Int(20000), Autoretry: tea.Bool(false),
		})
		if err != nil {
			var sdk *tea.SDKError
			if errors.As(err, &sdk) {
				return nil, codeError(tea.StringValue(sdk.Code))
			}
			return nil, apiError(err)
		}
		if response == nil || response.Body == nil || response.Body.Instances == nil {
			return nil, &Error{Code: "invalid_response"}
		}
		for _, instance := range response.Body.Instances.Instance {
			if instance == nil {
				return nil, &Error{Code: "invalid_response"}
			}
			value := Instance{ID: tea.StringValue(instance.InstanceId), Name: tea.StringValue(instance.InstanceName)}
			if instance.VpcAttributes != nil && instance.VpcAttributes.PrivateIpAddress != nil {
				for _, address := range instance.VpcAttributes.PrivateIpAddress.IpAddress {
					if value.Host == "" {
						value.Host = tea.StringValue(address)
					}
				}
			}
			if value.Host == "" && instance.InnerIpAddress != nil {
				for _, address := range instance.InnerIpAddress.IpAddress {
					if value.Host == "" {
						value.Host = tea.StringValue(address)
					}
				}
			}
			values = append(values, value)
		}
		if len(values) > MaxInstances {
			return nil, &Error{Code: "too_many_instances"}
		}
		token := tea.StringValue(response.Body.NextToken)
		if len(ids) > 0 {
			if int(tea.Int32Value(response.Body.TotalCount)) > len(values) {
				return nil, &Error{Code: "incomplete_pagination"}
			}
			return values, nil
		}
		if token == "" {
			return values, nil
		}
		if err := nextPage(token, seen); err != nil {
			return nil, err
		}
		request.NextToken = tea.String(token)
	}
	return nil, &Error{Code: "incomplete_pagination"}
}
