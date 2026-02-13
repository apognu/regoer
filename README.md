# Regoer

A Rust library for converting AWS IAM policies to Rego (Open Policy Agent) and evaluating them outside of AWS.

## Overview

This library parses AWS IAM policy documents and transpiles them into Rego policies, allowing you to use familiar IAM policy syntax in non-AWS products and services that support OPA/Rego.

For example, the following policy (from `examples/policy.json`) would turn into that Rego policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Sid1",
      "Effect": "Allow",
      "Principal": { "AWS": "apognu" },
      "Action": "s3:Get*",
      "Resource": "arn:aws:s3:::public/${aws:userid}/*.jpg",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalType": "AssumedRole",
          "aws:userid": "apognu"
        },
        "NotIpAddress": {
          "aws:sourceIp": ["10.0.0.0/8", "192.168.0.0/24"]
        }
      }
    },
    {
      "Sid": "DenyForProduction",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:BucketTag/env": "production"
        }
      }
    }
  ]
}
```

```rego
package main

default allow = false
default deny = false
default permit = false

allow if {
  permit
  not deny
}

permit if {
  input.principal == "apognu"
  glob.match("s3:Get*", null, input.action)
  glob.match(sprintf("arn:aws:s3:::public/%s/*.jpg", [data.aws.userid]), null, input.resource)
  every item in ["10.0.0.0/8", "192.168.0.0/24"] { not net.cidr_contains(item, data.aws.sourceIp) }
  data.aws.userid == "apognu"
  data.aws.PrincipalType == "AssumedRole"
}

deny if {
  data.aws.BucketTag.env == "production"
}
```

## Usage

```rust,ignore
use regoer::Regoer;
use serde_json::json;

let mut regoer = Regoer::default();
regoer.add_policy(policy_file).expect("invalid policy");
let evaluator = regoer.compile().expect("compilation error");

let input = json!({
    "principal": "apognu",
    "action": "s3:GetObject",
    "resource": "arn:aws:s3:::public/apognu/image.jpg",
    "aws": {
        "PrincipalType": "AssumedRole",
        "userid": "apognu",
        "SourceIp": "11.12.13.14",
        "BucketTag": {
            "env": "staging"
        }
    }
});

let allowed = evaluator.evaluate(input).expect("evaluation error"); // true / false
```

It expects input to be provided as any type that can be `Serialize`d, with the structure shown above.

## Example

```bash
cargo run --example main -- examples/policy.json
```
