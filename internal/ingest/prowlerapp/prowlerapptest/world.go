package prowlerapptest

import (
	"fmt"
	"testing"
	"time"
)

// Sample is a Prowler App with two providers: an AWS account (account
// 123456789012, id "p-aws") with five failing S3 findings and a GCP project
// (my-project, id "p-gcp") with one, both from scans completed at completedAt.
// With the default page size of 2 the AWS findings take three pages. apiKey
// is the accepted API key.
func Sample(t testing.TB, apiKey string, completedAt time.Time) *Server {
	t.Helper()
	srv := New(t)
	srv.APIKey = apiKey
	started := completedAt.Add(-time.Hour)
	srv.Providers = []Provider{
		{ID: "p-gcp", Type: "gcp", UID: "my-project", Connected: true},
		{ID: "p-aws", Type: "aws", UID: "123456789012", Connected: true},
	}
	srv.Scans = []Scan{
		{ID: "s-aws", ProviderID: "p-aws", State: "completed", StartedAt: started, CompletedAt: completedAt},
		{ID: "s-aws-old", ProviderID: "p-aws", State: "completed", StartedAt: started.Add(-24 * time.Hour), CompletedAt: completedAt.Add(-24 * time.Hour)},
		{ID: "s-gcp", ProviderID: "p-gcp", State: "completed", StartedAt: started, CompletedAt: completedAt.Add(time.Minute)},
	}
	for i := 1; i <= 5; i++ {
		srv.Resources = append(srv.Resources, Resource{ID: fmt.Sprintf("r%d", i), UID: fmt.Sprintf("arn:aws:s3:::bucket-%d", i), Name: fmt.Sprintf("bucket-%d", i), Region: "us-east-1", Service: "s3", Type: "AwsS3Bucket"})
		srv.Findings = append(srv.Findings, AWSFinding(i))
	}
	srv.Resources = append(srv.Resources, Resource{ID: "rg", UID: "projects/my-project/buckets/b", Name: "b", Region: "europe-west1", Service: "gcs", Type: "bucket"})
	srv.Findings = append(srv.Findings, Finding{
		ID: "fg", UID: "prowler-gcp-gcs-1", ProviderID: "p-gcp", ScanID: "s-gcp", CheckID: "gcs_public", CheckTitle: "GCS bucket is public",
		Severity: "high", Status: "FAIL", StatusExtended: "bucket b is public", Service: "gcs", ResourceIDs: []string{"rg"},
	})
	return srv
}

// AWSFinding is the public-bucket finding of Sample's i-th bucket (1 to 5).
func AWSFinding(i int) Finding {
	return Finding{
		ID: fmt.Sprintf("f%d", i), UID: fmt.Sprintf("prowler-aws-s3_public-123456789012-us-east-1-b%d", i), ProviderID: "p-aws", ScanID: "s-aws",
		CheckID: "s3_public", CheckTitle: "S3 bucket is public", Severity: "high", Status: "FAIL", StatusExtended: fmt.Sprintf("bucket-%d is public", i),
		Risk: "data leak", RecText: "Block public access", RecURL: "https://docs.example.com/s3", Service: "s3", ResourceType: "AwsS3Bucket",
		Delta: "new", FirstSeenAt: "2026-10-01T00:00:00Z", ResourceIDs: []string{fmt.Sprintf("r%d", i)},
	}
}
