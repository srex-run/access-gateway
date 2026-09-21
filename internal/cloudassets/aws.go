package cloudassets

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func (c *Client) aws(ctx context.Context, credentials Credentials, region string, ids []string) ([]Instance, error) {
	client := ec2.NewFromConfig(aws.Config{
		Region: region, HTTPClient: c.http, RetryMaxAttempts: 3,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: credentials.AccessKey, SecretAccessKey: credentials.SecretKey,
				SessionToken: credentials.SessionToken, Source: "access-gateway-cloud-account"}, nil
		}),
	})
	request := &ec2.DescribeInstancesInput{MaxResults: aws.Int32(1000)}
	if len(ids) > 0 {
		// Filters return an empty match for missing IDs; InstanceIds aborts the entire request.
		request.Filters = []types.Filter{{Name: aws.String("instance-id"), Values: ids}}
	}
	var values []Instance
	seen := make(map[string]bool)
	for page := 0; page < 200; page++ {
		result, err := client.DescribeInstances(ctx, request)
		if err != nil {
			return nil, apiError(err)
		}
		if result == nil {
			return nil, &Error{Code: "invalid_response"}
		}
		for _, reservation := range result.Reservations {
			for _, instance := range reservation.Instances {
				value := Instance{ID: aws.ToString(instance.InstanceId), Host: aws.ToString(instance.PrivateIpAddress)}
				for _, tag := range instance.Tags {
					if aws.ToString(tag.Key) == "Name" {
						value.Name = aws.ToString(tag.Value)
					}
				}
				values = append(values, value)
			}
		}
		if len(values) > MaxInstances {
			return nil, &Error{Code: "too_many_instances"}
		}
		token := aws.ToString(result.NextToken)
		if token == "" {
			return values, nil
		}
		if err := nextPage(token, seen); err != nil {
			return nil, err
		}
		request.NextToken = result.NextToken
	}
	return nil, &Error{Code: "incomplete_pagination"}
}
