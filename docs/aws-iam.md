# AWS source: minimum IAM policy

The `aws` source only calls read-only Describe/List APIs.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:DescribeAddresses",
      "ec2:DescribeInstances",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeListeners",
      "cloudfront:ListDistributions"
    ],
    "Resource": "*"
  }]
}
```

- The EC2 and ELBv2 actions are required: if one is denied the sync fails
  with an error naming the missing permission (no partial inventory).
- `cloudfront:ListDistributions` is optional: if denied, CloudFront is skipped
  with a warning.
- `sts:AssumeRole` on the target role is needed only when `role_arn` is set
  (grant it to the identity deckard runs as; the role carries the policy above).
- Multi-account: add one source entry per account, each with its own `role_arn`.
