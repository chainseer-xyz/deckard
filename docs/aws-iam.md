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

## Route 53 discovery

Route 53 is a separate `type: route53` source. It needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "route53:ListHostedZones",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "route53:ListResourceRecordSets",
      "Resource": "arn:aws:route53:::hostedzone/*"
    }
  ]
}
```

The source skips private zones. It attempts every public hosted zone, so restricting
record reads to selected zones causes discovery to fail on other public zones.
It does not read S3 objects, secrets or resource contents.

## EKS IRSA

Trust only the cluster's exact OIDC provider, the intended service account's
`sub`, and audience `sts.amazonaws.com`. Annotate that service account with
`eks.amazonaws.com/role-arn`. Do not add account-root trust, wildcard subjects,
broad managed policies or static credentials.

Leave source `profile` and `role_arn` unset for direct IRSA authentication.
Setting `role_arn` adds a second AssumeRole hop; the web identity role does not
need `sts:AssumeRole` to use its own credentials. Set
`AWS_EC2_METADATA_DISABLED=true` to prevent fallback to the node's role.

Set source `regions` explicitly. You can restrict the regional EC2/ELB permissions
with `aws:RequestedRegion` to the same list. Keep global CloudFront and Route 53
permissions separate from that regional condition. The discovery Describe/List
APIs require `Resource: "*"`, except Route 53 record reads shown above.

IAM read-only access does not make Deckard's network scans passive. AWS-owned
public IP discovery changes scan eligibility. For a passive-only first inventory,
disable the active tier globally; source-only groups do not contain overlapping
or derived assets.
