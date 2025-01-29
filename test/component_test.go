package test

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/aws-component-helper"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComponent(t *testing.T) {
	t.Parallel()
	// Define the AWS region to use for the tests
	awsRegion := "us-east-2"

	// Initialize the test fixture
	fixture := helper.NewFixture(t, "../", awsRegion, "test/fixtures")

	// Ensure teardown is executed after the test
	defer fixture.TearDown()
	fixture.SetUp(&atmos.Options{})

	// Define the test suite
	fixture.Suite("default", func(t *testing.T, suite *helper.Suite) {
		t.Parallel()
		suite.AddDependency("cloudtrail-bucket", "default-test")

		// Test phase: Validate the functionality of the bastion component
		suite.Test(t, "basic", func(t *testing.T, atm *helper.Atmos) {
			defer atm.GetAndDestroy("cloudtrail/basic", "default-test", map[string]interface{}{})
			component := atm.GetAndDeploy("cloudtrail/basic", "default-test", map[string]interface{}{})
			assert.NotNil(t, component)

			cloudtrailID := atm.Output(component, "cloudtrail_id")

			client := NewCloudTrailClient(t, awsRegion)
			trails, err := client.DescribeTrails(context.Background(), &cloudtrail.DescribeTrailsInput{
				TrailNameList: []string{cloudtrailID},
			})
			assert.NoError(t, err)
			trail := trails.TrailList[0]

			cloudtrailArn := atm.Output(component, "cloudtrail_arn")
			assert.Equal(t, cloudtrailArn, *trail.TrailARN)

			cloudtrailLogsLogGroupArn := atm.Output(component, "cloudtrail_logs_log_group_arn")
			assert.True(t, strings.HasPrefix(*trail.CloudWatchLogsLogGroupArn, cloudtrailLogsLogGroupArn))

			cloudtrailLogsLogGroupName := atm.Output(component, "cloudtrail_logs_log_group_name")
			assert.True(t, strings.HasSuffix(cloudtrailLogsLogGroupArn, cloudtrailLogsLogGroupName))

			cloudtrailLogsRoleArn := atm.Output(component, "cloudtrail_logs_role_arn")
			assert.Equal(t, cloudtrailLogsRoleArn, *trail.CloudWatchLogsRoleArn)

			cloudtrailLogsRoleName := atm.Output(component, "cloudtrail_logs_role_name")
			assert.True(t, strings.HasSuffix(cloudtrailLogsRoleArn, cloudtrailLogsRoleName))

			cloudtrailHomeRegion := atm.Output(component, "cloudtrail_home_region")
			assert.Equal(t, "us-east-2", cloudtrailHomeRegion)
			assert.Equal(t, *trail.HomeRegion, cloudtrailHomeRegion)

			assert.False(t, *trail.IsOrganizationTrail)
		})

		suite.Test(t, "org-level", func(t *testing.T, atm *helper.Atmos) {
			t.Skip("Skipping org-level test because it's not supported due to Service Policy limitations")
			defer atm.GetAndDestroy("cloudtrail/org-level", "default-test", map[string]interface{}{})
			component := atm.GetAndDeploy("cloudtrail/org-level", "default-test", map[string]interface{}{})
			assert.NotNil(t, component)

			cloudtrailID := atm.Output(component, "cloudtrail_id")

			client := NewCloudTrailClient(t, awsRegion)
			trails, err := client.DescribeTrails(context.Background(), &cloudtrail.DescribeTrailsInput{
				TrailNameList: []string{cloudtrailID},
			})
			assert.NoError(t, err)
			trail := trails.TrailList[0]

			cloudtrailArn := atm.Output(component, "cloudtrail_arn")
			assert.Equal(t, cloudtrailArn, *trail.TrailARN)

			cloudtrailLogsLogGroupArn := atm.Output(component, "cloudtrail_logs_log_group_arn")
			assert.True(t, strings.HasPrefix(*trail.CloudWatchLogsLogGroupArn, cloudtrailLogsLogGroupArn))

			cloudtrailLogsLogGroupName := atm.Output(component, "cloudtrail_logs_log_group_name")
			assert.True(t, strings.HasSuffix(cloudtrailLogsLogGroupArn, cloudtrailLogsLogGroupName))

			cloudtrailLogsRoleArn := atm.Output(component, "cloudtrail_logs_role_arn")
			assert.Equal(t, cloudtrailLogsRoleArn, *trail.CloudWatchLogsRoleArn)

			cloudtrailLogsRoleName := atm.Output(component, "cloudtrail_logs_role_name")
			assert.True(t, strings.HasSuffix(cloudtrailLogsRoleArn, cloudtrailLogsRoleName))

			cloudtrailHomeRegion := atm.Output(component, "cloudtrail_home_region")
			assert.Equal(t, "us-east-2", cloudtrailHomeRegion)
			assert.Equal(t, *trail.HomeRegion, cloudtrailHomeRegion)

			assert.True(t, *trail.IsOrganizationTrail)
		})

	})
}

func NewCloudTrailClient(t *testing.T, region string) *cloudtrail.Client {
	client, err := NewCloudTrailClientE(t, region)
	require.NoError(t, err)

	return client
}

func NewCloudTrailClientE(t *testing.T, region string) (*cloudtrail.Client, error) {
	sess, err := aws.NewAuthenticatedSession(region)
	if err != nil {
		return nil, err
	}
	return cloudtrail.NewFromConfig(*sess), nil
}
