package aws

import "testing"

func TestInstanceARNPartitions(t *testing.T) {
	for _, tc := range []struct{ region, partition string }{{"us-east-1", "aws"}, {"us-gov-west-1", "aws-us-gov"}, {"cn-north-1", "aws-cn"}} {
		want := "arn:" + tc.partition + ":ec2:" + tc.region + ":123456789012:instance/i-123456"
		if got := instanceARN(tc.region, "123456789012", "i-123456"); got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
	for _, account := range []string{"", "invalid", "123"} {
		if got := instanceARN("us-east-1", account, "i-123456"); got != "" {
			t.Errorf("accepted account %q: %s", account, got)
		}
	}
}
