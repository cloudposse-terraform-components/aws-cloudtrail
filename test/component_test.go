package test

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/component-helper"
	awshelper "github.com/cloudposse/test-helpers/pkg/aws"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/stretchr/testify/assert"
)

type ComponentSuite struct {
	helper.TestSuite
}

const (
	testStack    = "default-test"
	testAwsRegion = "us-east-2"
)

// TearDownSuite empties the S3 bucket before the dependency is destroyed.
// This is necessary because the bucket has versioning enabled and may contain
// objects from CloudTrail logging during the tests.
func (s *ComponentSuite) TearDownSuite() {
	cloudtrailBucketOptions := s.GetAtmosOptions("cloudtrail-bucket", testStack, nil)
	bucketName := atmos.Output(s.T(), cloudtrailBucketOptions, "cloudtrail_bucket_id")
	aws.EmptyS3Bucket(s.T(), testAwsRegion, bucketName)
}

func (s *ComponentSuite) TestBasic() {
	const component = "cloudtrail/basic"

	defer s.DestroyAtmosComponent(s.T(), component, testStack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, testStack, nil)
	assert.NotNil(s.T(), options)

	cloudtrailID := atmos.Output(s.T(), options, "cloudtrail_id")

	client := awshelper.NewCloudTrailClient(s.T(), testAwsRegion)
	trails, err := client.DescribeTrails(context.Background(), &cloudtrail.DescribeTrailsInput{
		TrailNameList: []string{cloudtrailID},
	})
	assert.NoError(s.T(), err)
	trail := trails.TrailList[0]

	cloudtrailArn := atmos.Output(s.T(), options, "cloudtrail_arn")
	assert.Equal(s.T(), cloudtrailArn, *trail.TrailARN)

	cloudtrailLogsLogGroupArn := atmos.Output(s.T(), options, "cloudtrail_logs_log_group_arn")
	assert.True(s.T(), strings.HasPrefix(*trail.CloudWatchLogsLogGroupArn, cloudtrailLogsLogGroupArn))

	cloudtrailLogsLogGroupName := atmos.Output(s.T(), options, "cloudtrail_logs_log_group_name")
	assert.True(s.T(), strings.HasSuffix(cloudtrailLogsLogGroupArn, cloudtrailLogsLogGroupName))

	cloudtrailLogsRoleArn := atmos.Output(s.T(), options, "cloudtrail_logs_role_arn")
	assert.Equal(s.T(), cloudtrailLogsRoleArn, *trail.CloudWatchLogsRoleArn)

	cloudtrailLogsRoleName := atmos.Output(s.T(), options, "cloudtrail_logs_role_name")
	assert.True(s.T(), strings.HasSuffix(cloudtrailLogsRoleArn, cloudtrailLogsRoleName))

	cloudtrailHomeRegion := atmos.Output(s.T(), options, "cloudtrail_home_region")
	assert.Equal(s.T(), testAwsRegion, cloudtrailHomeRegion)
	assert.Equal(s.T(), *trail.HomeRegion, cloudtrailHomeRegion)

	assert.False(s.T(), *trail.IsOrganizationTrail)

	s.DriftTest(component, testStack, nil)
}

func (s *ComponentSuite) TestOrgLevel() {
	const component = "cloudtrail/org-level"

	s.T().Skip("Skipping org-level test because it's not supported due to Service Policy limitations")
	defer s.DestroyAtmosComponent(s.T(), component, testStack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, testStack, nil)
	assert.NotNil(s.T(), options)

	cloudtrailID := atmos.Output(s.T(), options, "cloudtrail_id")

	client := awshelper.NewCloudTrailClient(s.T(), testAwsRegion)
	trails, err := client.DescribeTrails(context.Background(), &cloudtrail.DescribeTrailsInput{
		TrailNameList: []string{cloudtrailID},
	})
	assert.NoError(s.T(), err)
	trail := trails.TrailList[0]

	cloudtrailArn := atmos.Output(s.T(), options, "cloudtrail_arn")
	assert.Equal(s.T(), cloudtrailArn, *trail.TrailARN)

	cloudtrailLogsLogGroupArn := atmos.Output(s.T(), options, "cloudtrail_logs_log_group_arn")
	assert.True(s.T(), strings.HasPrefix(*trail.CloudWatchLogsLogGroupArn, cloudtrailLogsLogGroupArn))

	cloudtrailLogsLogGroupName := atmos.Output(s.T(), options, "cloudtrail_logs_log_group_name")
	assert.True(s.T(), strings.HasSuffix(cloudtrailLogsLogGroupArn, cloudtrailLogsLogGroupName))

	cloudtrailLogsRoleArn := atmos.Output(s.T(), options, "cloudtrail_logs_role_arn")
	assert.Equal(s.T(), cloudtrailLogsRoleArn, *trail.CloudWatchLogsRoleArn)

	cloudtrailLogsRoleName := atmos.Output(s.T(), options, "cloudtrail_logs_role_name")
	assert.True(s.T(), strings.HasSuffix(cloudtrailLogsRoleArn, cloudtrailLogsRoleName))

	cloudtrailHomeRegion := atmos.Output(s.T(), options, "cloudtrail_home_region")
	assert.Equal(s.T(), testAwsRegion, cloudtrailHomeRegion)
	assert.Equal(s.T(), *trail.HomeRegion, cloudtrailHomeRegion)

	assert.True(s.T(), *trail.IsOrganizationTrail)

	s.DriftTest(component, testStack, nil)
}

func (s *ComponentSuite) TestEnabledFlag() {
	const component = "cloudtrail/disabled"

	s.VerifyEnabledFlag(component, testStack, nil)
}

func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)

	suite.AddDependency(t, "cloudtrail-bucket", testStack, nil)
	helper.Run(t, suite)
}
