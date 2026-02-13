use regoer::{Error, Regoer};
use serde_json::json;

fn compile_policy(policy_json: serde_json::Value) -> Result<regoer::Evaluator, Error> {
  let mut regoer = Regoer::default();
  let policy_str = serde_json::to_string(&policy_json).unwrap();
  regoer.add_policy(policy_str.as_bytes())?;
  regoer.compile()
}

fn evaluate(evaluator: &regoer::Evaluator, input: serde_json::Value) -> Result<bool, Error> {
  evaluator.evaluate(input)
}

#[test]
fn simple_allow_basic_validation() {
  // Test a basic Allow statement with exact matches for principal, action, and resource
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::test-bucket/test-file.txt"
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Exact match should allow
  let input = json!({
      "principal": "testuser",
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::test-bucket/test-file.txt"
  });
  assert_eq!(evaluate(&evaluator, input).unwrap(), true, "Should allow exact match");

  // Wrong principal should deny
  let input = json!({
      "principal": "wronguser",
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::test-bucket/test-file.txt"
  });
  assert_eq!(evaluate(&evaluator, input).unwrap(), false, "Should deny wrong principal");

  // Wrong action should deny
  let input = json!({
      "principal": "testuser",
      "action": "s3:PutObject",
      "resource": "arn:aws:s3:::test-bucket/test-file.txt"
  });
  assert_eq!(evaluate(&evaluator, input).unwrap(), false, "Should deny wrong action");

  // Wrong resource should deny
  let input = json!({
      "principal": "testuser",
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::test-bucket/other-file.txt"
  });
  assert_eq!(evaluate(&evaluator, input).unwrap(), false, "Should deny wrong resource");
}

#[test]
fn wildcard_with_condition_validation() {
  // Test wildcard action matching combined with multiple conditions
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "*"},
          "Action": "s3:Get*",
          "Resource": "arn:aws:s3:::bucket/*",
          "Condition": {
              "StringEquals": {
                  "aws:userid": "authorizeduser"
              },
              "IpAddress": {
                  "aws:SourceIp": "192.168.1.0/24"
              }
          }
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Matches wildcard action, resource, and all conditions
  let input = json!({
      "principal": "anyone",
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::bucket/file.txt",
      "aws": {
          "userid": "authorizeduser",
          "SourceIp": "192.168.1.100"
      }
  });
  assert_eq!(evaluate(&evaluator, input).unwrap(), true, "Should allow when all conditions match");

  // Different Get* action should also work
  let input = json!({
      "principal": "anyone",
      "action": "s3:GetObjectVersion",
      "resource": "arn:aws:s3:::bucket/file.txt",
      "aws": {
          "userid": "authorizeduser",
          "SourceIp": "192.168.1.100"
      }
  });
  assert_eq!(evaluate(&evaluator, input).unwrap(), true, "Should allow other Get* actions");

  // Wrong IP should deny
  let input = json!({
      "principal": "anyone",
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::bucket/file.txt",
      "aws": {
          "userid": "authorizeduser",
          "SourceIp": "10.0.0.1"
      }
  });
  assert_eq!(evaluate(&evaluator, input).unwrap(), false, "Should deny wrong IP address");

  // Wrong userid should deny
  let input = json!({
      "principal": "anyone",
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::bucket/file.txt",
      "aws": {
          "userid": "wronguser",
          "SourceIp": "192.168.1.100"
      }
  });
  assert_eq!(evaluate(&evaluator, input).unwrap(), false, "Should deny wrong userid");

  // Action doesn't match Get* pattern
  let input = json!({
      "principal": "anyone",
      "action": "s3:PutObject",
      "resource": "arn:aws:s3:::bucket/file.txt",
      "aws": {
          "userid": "authorizeduser",
          "SourceIp": "192.168.1.100"
      }
  });
  assert_eq!(evaluate(&evaluator, input).unwrap(), false, "Should deny non-Get* action");

  // Resource outside wildcard scope
  let input = json!({
      "principal": "anyone",
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::other-bucket/file.txt",
      "aws": {
          "userid": "authorizeduser",
          "SourceIp": "192.168.1.100"
      }
  });
  assert_eq!(evaluate(&evaluator, input).unwrap(), false, "Should deny wrong bucket");
}

#[test]
fn multiple_principals_array() {
  // Test that array of principals allows any matching principal
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": ["alice", "bob", "charlie"]},
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::shared-bucket/*"
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // All three principals should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "alice",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::shared-bucket/file.txt"
      })
    )
    .unwrap(),
    "Should allow alice"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "bob",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::shared-bucket/file.txt"
      })
    )
    .unwrap(),
    "Should allow bob"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "charlie",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::shared-bucket/file.txt"
      })
    )
    .unwrap(),
    "Should allow charlie"
  );

  // Other principals should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "eve",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::shared-bucket/file.txt"
      })
    )
    .unwrap(),
    "Should deny eve"
  );
}

#[test]
fn multiple_actions_array() {
  // Test that array of actions allows any matching action
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
          "Resource": "arn:aws:s3:::bucket/*"
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // All three actions should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should allow GetObject"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:PutObject",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should allow PutObject"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:DeleteObject",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should allow DeleteObject"
  );

  // Other actions should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:ListBucket",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should deny ListBucket"
  );
}

#[test]
fn multiple_resources_array() {
  // Test that array of exact-match resources allows any matching resource
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:GetObject",
          "Resource": [
              "arn:aws:s3:::bucket1/file1.txt",
              "arn:aws:s3:::bucket2/file2.txt",
              "arn:aws:s3:::bucket3/specific-file.txt"
          ]
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // All three specific resources should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket1/file1.txt"
      })
    )
    .unwrap(),
    "Should allow bucket1/file1.txt"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket2/file2.txt"
      })
    )
    .unwrap(),
    "Should allow bucket2/file2.txt"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket3/specific-file.txt"
      })
    )
    .unwrap(),
    "Should allow specific file in bucket3"
  );

  // Other resources should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket3/other-file.txt"
      })
    )
    .unwrap(),
    "Should deny other file in bucket3"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket4/file.txt"
      })
    )
    .unwrap(),
    "Should deny bucket4"
  );
}

#[test]
fn multiple_resources_array_with_wildcards() {
  // Test that array of wildcard resources allows any matching resource
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:GetObject",
          "Resource": [
              "arn:aws:s3:::bucket1/*",
              "arn:aws:s3:::bucket2/*"
          ]
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Resources in either bucket should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket1/file.txt"
      })
    )
    .unwrap(),
    "Should allow bucket1"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket2/file.txt"
      })
    )
    .unwrap(),
    "Should allow bucket2"
  );
}

#[test]
fn action_wildcard_prefix() {
  // Test action with wildcard at the end
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "ec2:Describe*",
          "Resource": "*"
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Various Describe* actions should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "ec2:DescribeInstances",
          "resource": "*"
      })
    )
    .unwrap(),
    "Should allow DescribeInstances"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "ec2:DescribeVolumes",
          "resource": "*"
      })
    )
    .unwrap(),
    "Should allow DescribeVolumes"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "ec2:DescribeSecurityGroups",
          "resource": "*"
      })
    )
    .unwrap(),
    "Should allow DescribeSecurityGroups"
  );

  // Non-Describe actions should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "ec2:TerminateInstances",
          "resource": "*"
      })
    )
    .unwrap(),
    "Should deny TerminateInstances"
  );
}

#[test]
fn resource_wildcard_patterns() {
  // Test various resource wildcard patterns
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::my-bucket/public/*"
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Resources under /public/ should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::my-bucket/public/file.txt"
      })
    )
    .unwrap(),
    "Should allow file in public"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::my-bucket/public/subdir/file.txt"
      })
    )
    .unwrap(),
    "Should allow file in public/subdir"
  );

  // Resources outside /public/ should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::my-bucket/private/file.txt"
      })
    )
    .unwrap(),
    "Should deny file in private"
  );
}

#[test]
fn wildcard_star_all() {
  // Test "*" wildcard for all actions and resources
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "admin"},
          "Action": "*",
          "Resource": "*"
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Any action and resource should be allowed for admin
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "admin",
          "action": "s3:DeleteBucket",
          "resource": "arn:aws:s3:::any-bucket"
      })
    )
    .unwrap(),
    "Should allow any action"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "admin",
          "action": "ec2:TerminateInstances",
          "resource": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
      })
    )
    .unwrap(),
    "Should allow any resource"
  );
}

#[test]
fn not_action_single() {
  // Test NotAction with single value - allows everything except specified action
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "NotAction": "s3:DeleteObject",
          "Resource": "arn:aws:s3:::bucket/*"
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // All actions except DeleteObject should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should allow GetObject"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:PutObject",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should allow PutObject"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:ListBucket",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should allow ListBucket"
  );

  // DeleteObject should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:DeleteObject",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should deny DeleteObject"
  );
}

#[test]
fn not_action_multiple() {
  // Test NotAction with array of values
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "NotAction": ["s3:DeleteObject", "s3:DeleteBucket", "s3:PutBucketPolicy"],
          "Resource": "*"
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Safe actions should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should allow GetObject"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:ListBucket",
          "resource": "arn:aws:s3:::bucket"
      })
    )
    .unwrap(),
    "Should allow ListBucket"
  );

  // Destructive actions should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:DeleteObject",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should deny DeleteObject"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:DeleteBucket",
          "resource": "arn:aws:s3:::bucket"
      })
    )
    .unwrap(),
    "Should deny DeleteBucket"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:PutBucketPolicy",
          "resource": "arn:aws:s3:::bucket"
      })
    )
    .unwrap(),
    "Should deny PutBucketPolicy"
  );
}

#[test]
fn not_resource_single() {
  // Test NotResource - allows access to all resources except specified one
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:*",
          "NotResource": "arn:aws:s3:::production/*"
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Non-production resources should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::dev/file.txt"
      })
    )
    .unwrap(),
    "Should allow dev bucket"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::staging/file.txt"
      })
    )
    .unwrap(),
    "Should allow staging bucket"
  );

  // Production resources should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::production/file.txt"
      })
    )
    .unwrap(),
    "Should deny production bucket"
  );
}

#[test]
fn not_resource_multiple() {
  // Test NotResource with multiple values
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:*",
          "NotResource": [
              "arn:aws:s3:::production/*",
              "arn:aws:s3:::sensitive/*",
              "arn:aws:s3:::backups/*"
          ]
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Non-restricted resources should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::dev/file.txt"
      })
    )
    .unwrap(),
    "Should allow dev bucket"
  );

  // All restricted resources should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::production/file.txt"
      })
    )
    .unwrap(),
    "Should deny production"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::sensitive/data.txt"
      })
    )
    .unwrap(),
    "Should deny sensitive"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::backups/backup.tar.gz"
      })
    )
    .unwrap(),
    "Should deny backups"
  );
}

#[test]
fn date_greater_than_condition() {
  // Test DateGreaterThan - allow access only after a certain date
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::bucket/*",
          "Condition": {
              "DateGreaterThan": {
                  "aws:CurrentTime": "2025-01-01T00:00:00Z"
              }
          }
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Access after 2025-01-01 should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "CurrentTime": "2025-06-15T12:00:00Z"
          }
      })
    )
    .unwrap(),
    "Should allow access after date"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "CurrentTime": "2026-01-01T00:00:00Z"
          }
      })
    )
    .unwrap(),
    "Should allow access in 2026"
  );

  // Access before 2025-01-01 should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "CurrentTime": "2024-12-31T23:59:59Z"
          }
      })
    )
    .unwrap(),
    "Should deny access before date"
  );
}

#[test]
fn date_less_than_condition() {
  // Test DateLessThan - allow access only before a certain date
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::bucket/*",
          "Condition": {
              "DateLessThan": {
                  "aws:CurrentTime": "2025-12-31T23:59:59Z"
              }
          }
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Access before 2025-12-31 should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "CurrentTime": "2025-01-01T00:00:00Z"
          }
      })
    )
    .unwrap(),
    "Should allow access before date"
  );

  // Access after 2025-12-31 should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "CurrentTime": "2026-01-01T00:00:00Z"
          }
      })
    )
    .unwrap(),
    "Should deny access after date"
  );
}

#[test]
fn date_range_condition() {
  // Test date range using both DateGreaterThan and DateLessThan
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::bucket/*",
          "Condition": {
              "DateGreaterThan": {
                  "aws:CurrentTime": "2025-01-01T00:00:00Z"
              },
              "DateLessThan": {
                  "aws:CurrentTime": "2025-12-31T23:59:59Z"
              }
          }
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Access within 2025 should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "CurrentTime": "2025-06-15T12:00:00Z"
          }
      })
    )
    .unwrap(),
    "Should allow access within date range"
  );

  // Access before 2025 should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "CurrentTime": "2024-12-31T23:59:59Z"
          }
      })
    )
    .unwrap(),
    "Should deny access before range"
  );

  // Access after 2025 should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "CurrentTime": "2026-01-01T00:00:00Z"
          }
      })
    )
    .unwrap(),
    "Should deny access after range"
  );
}

#[test]
fn numeric_less_than_condition() {
  // Test NumericLessThan for file size limits
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:PutObject",
          "Resource": "arn:aws:s3:::bucket/*",
          "Condition": {
              "NumericLessThan": {
                  "s3:ContentLength": 10485760
              }
          }
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Files under 10MB should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:PutObject",
          "resource": "arn:aws:s3:::bucket/small-file.txt",
          "s3": {
              "ContentLength": 1048576  // 1MB
          }
      })
    )
    .unwrap(),
    "Should allow small file"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:PutObject",
          "resource": "arn:aws:s3:::bucket/medium-file.txt",
          "s3": {
              "ContentLength": 5242880  // 5MB
          }
      })
    )
    .unwrap(),
    "Should allow medium file"
  );

  // Files over 10MB should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:PutObject",
          "resource": "arn:aws:s3:::bucket/large-file.txt",
          "s3": {
              "ContentLength": 20971520  // 20MB
          }
      })
    )
    .unwrap(),
    "Should deny large file"
  );
}

#[test]
fn numeric_greater_than_condition() {
  // Test NumericGreaterThan
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "dynamodb:Query",
          "Resource": "*",
          "Condition": {
              "NumericGreaterThan": {
                  "dynamodb:Select": 0
              }
          }
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Values greater than 0 should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "dynamodb:Query",
          "resource": "*",
          "dynamodb": {
              "Select": 1
          }
      })
    )
    .unwrap(),
    "Should allow value > 0"
  );

  // Value of 0 should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "dynamodb:Query",
          "resource": "*",
          "dynamodb": {
              "Select": 0
          }
      })
    )
    .unwrap(),
    "Should deny value = 0"
  );
}

#[test]
fn ip_address_condition() {
  // Test IpAddress condition with CIDR range
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::bucket/*",
          "Condition": {
              "IpAddress": {
                  "aws:SourceIp": ["192.168.1.0/24", "10.0.0.0/8"]
              }
          }
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // IPs in allowed ranges should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "SourceIp": "192.168.1.100"
          }
      })
    )
    .unwrap(),
    "Should allow IP in 192.168.1.0/24"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "SourceIp": "10.5.10.20"
          }
      })
    )
    .unwrap(),
    "Should allow IP in 10.0.0.0/8"
  );

  // IPs outside allowed ranges should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "SourceIp": "172.16.0.1"
          }
      })
    )
    .unwrap(),
    "Should deny IP outside ranges"
  );
}

#[test]
fn not_ip_address_condition() {
  // Test NotIpAddress - deny specific IP ranges
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::bucket/*",
          "Condition": {
              "NotIpAddress": {
                  "aws:SourceIp": ["10.0.0.0/8", "192.168.0.0/24"]
              }
          }
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // IPs in blocked ranges should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "SourceIp": "10.5.10.20"
          }
      })
    )
    .unwrap(),
    "Should deny IP in 10.0.0.0/8"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "SourceIp": "192.168.0.50"
          }
      })
    )
    .unwrap(),
    "Should deny IP in 192.168.0.0/24"
  );

  // IPs outside blocked ranges should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "SourceIp": "172.16.0.1"
          }
      })
    )
    .unwrap(),
    "Should allow IP outside blocked ranges"
  );
}

#[test]
fn resource_interpolation_basic() {
  // Test basic variable interpolation in resource paths
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "*"},
          "Action": "s3:*",
          "Resource": "arn:aws:s3:::bucket/${aws:userid}/*"
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // User accessing their own directory should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "alice",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/alice/file.txt",
          "aws": {
              "userid": "alice"
          }
      })
    )
    .unwrap(),
    "Should allow user to access their own directory"
  );

  // User accessing another user's directory should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "alice",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/bob/file.txt",
          "aws": {
              "userid": "alice"
          }
      })
    )
    .unwrap(),
    "Should deny user accessing another user's directory"
  );
}

#[test]
fn resource_interpolation_multiple_variables() {
  // Test multiple variables in resource path
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "*"},
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::${bucket}/${aws:userid}/${env}/*"
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Matching all variables should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "alice",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::my-bucket/alice/dev/data.txt",
          "bucket": "my-bucket",
          "aws": {
              "userid": "alice"
          },
          "env": "dev"
      })
    )
    .unwrap(),
    "Should allow when all variables match"
  );

  // Mismatched variables should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "alice",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::my-bucket/alice/prod/data.txt",
          "bucket": "my-bucket",
          "aws": {
              "userid": "alice"
          },
          "env": "dev"
      })
    )
    .unwrap(),
    "Should deny when variables don't match"
  );
}

#[test]
fn resource_interpolation_with_file_extension() {
  // Test interpolation with specific file extensions
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "*"},
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::bucket/photos/${aws:userid}/*.jpg"
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // User accessing their own .jpg files should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "alice",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/photos/alice/photo1.jpg",
          "aws": {
              "userid": "alice"
          }
      })
    )
    .unwrap(),
    "Should allow user's own .jpg file"
  );

  // User accessing other file types should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "alice",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/photos/alice/document.pdf",
          "aws": {
              "userid": "alice"
          }
      })
    )
    .unwrap(),
    "Should deny non-.jpg file"
  );
}

#[test]
fn multiple_allow_statements() {
  // Test multiple Allow statements - any matching statement grants access
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Principal": {"AWS": "testuser"},
              "Action": "s3:GetObject",
              "Resource": "arn:aws:s3:::bucket1/*"
          },
          {
              "Effect": "Allow",
              "Principal": {"AWS": "testuser"},
              "Action": "s3:GetObject",
              "Resource": "arn:aws:s3:::bucket2/*"
          }
      ]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Both buckets should be accessible
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket1/file.txt"
      })
    )
    .unwrap(),
    "Should allow access to bucket1"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket2/file.txt"
      })
    )
    .unwrap(),
    "Should allow access to bucket2"
  );

  // Other buckets should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket3/file.txt"
      })
    )
    .unwrap(),
    "Should deny access to bucket3"
  );
}

#[test]
fn deny_overrides_allow() {
  // Test that Deny always overrides Allow (IAM policy evaluation logic)
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Principal": {"AWS": "testuser"},
              "Action": "s3:*",
              "Resource": "arn:aws:s3:::bucket/*"
          },
          {
              "Effect": "Deny",
              "Principal": {"AWS": "*"},
              "Action": "s3:DeleteObject",
              "Resource": "arn:aws:s3:::bucket/*"
          }
      ]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Allow statement grants GetObject
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should allow GetObject"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:PutObject",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should allow PutObject"
  );

  // Deny overrides the Allow for DeleteObject
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:DeleteObject",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should deny DeleteObject (Deny overrides Allow)"
  );
}

#[test]
fn deny_all() {
  // Test that Deny always overrides Allow (IAM policy evaluation logic)
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Principal": {"AWS": "testuser"},
              "Action": "s3:*",
              "Resource": "arn:aws:s3:::bucket/*"
          },
          {
              "Effect": "Deny",
              "Principal": "*",
              "Action": "*",
              "Resource": "*"
          }
      ]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Allow statement grants GetObject
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should allow GetObject"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:PutObject",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should allow PutObject"
  );

  // Deny overrides the Allow for DeleteObject
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:DeleteObject",
          "resource": "arn:aws:s3:::bucket/file.txt"
      })
    )
    .unwrap(),
    "Should deny DeleteObject (Deny overrides Allow)"
  );
}

#[test]
fn conditional_deny() {
  // Test Deny with conditions
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Principal": {"AWS": "testuser"},
              "Action": "s3:*",
              "Resource": "*"
          },
          {
              "Effect": "Deny",
              "Principal": {"AWS": "*"},
              "Action": "*",
              "Resource": "arn:aws:s3:::production/*",
              "Condition": {
                  "StringEquals": {
                      "aws:RequestedRegion": "us-east-1"
                  }
              }
          }
      ]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Access to production bucket from us-east-1 should be denied
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::production/file.txt",
          "aws": {
              "RequestedRegion": "us-east-1"
          }
      })
    )
    .unwrap(),
    "Should deny production access from us-east-1"
  );

  // Access to production bucket from other regions should be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::production/file.txt",
          "aws": {
              "RequestedRegion": "eu-west-1"
          }
      })
    )
    .unwrap(),
    "Should allow production access from eu-west-1"
  );

  // Access to non-production buckets should always be allowed
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::dev/file.txt",
          "aws": {
              "RequestedRegion": "us-east-1"
          }
      })
    )
    .unwrap(),
    "Should allow dev access from any region"
  );
}

#[test]
fn numeric_not_equals_with_array() {
  // Test NumericNotEquals with array
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:PutObject",
          "Resource": "arn:aws:s3:::bucket/*",
          "Condition": {
              "NumericNotEquals": {
                  "s3:VersionId": [100, 200, 300]
              }
          }
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Values in the forbidden list should be DENIED
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:PutObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "s3": {
              "VersionId": 100
          }
      })
    )
    .unwrap(),
    "Should deny VersionId=100 (equals item in list)"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:PutObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "s3": {
              "VersionId": 200
          }
      })
    )
    .unwrap(),
    "Should deny VersionId=200 (equals item in list)"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:PutObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "s3": {
              "VersionId": 300
          }
      })
    )
    .unwrap(),
    "Should deny VersionId=300 (equals item in list)"
  );

  // Values NOT in the list should be ALLOWED
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:PutObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "s3": {
              "VersionId": 50
          }
      })
    )
    .unwrap(),
    "Should allow VersionId=50 (not equal to any in list)"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:PutObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "s3": {
              "VersionId": 500
          }
      })
    )
    .unwrap(),
    "Should allow VersionId=500 (not equal to any in list)"
  );
}

#[test]
fn string_not_equals_ignore_case_with_array() {
  // Test StringNotEqualsIgnoreCase with array
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::bucket/*",
          "Condition": {
              "StringNotEqualsIgnoreCase": {
                  "aws:username": ["ADMIN", "ROOT", "SYSTEM"]
              }
          }
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Forbidden usernames should be DENIED (case-insensitive)
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "username": "admin"
          }
      })
    )
    .unwrap(),
    "Should deny 'admin' (matches ADMIN case-insensitively)"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "username": "Root"
          }
      })
    )
    .unwrap(),
    "Should deny 'Root' (matches ROOT case-insensitively)"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "username": "SYSTEM"
          }
      })
    )
    .unwrap(),
    "Should deny 'SYSTEM'"
  );

  // Non-forbidden usernames should be ALLOWED
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "username": "alice"
          }
      })
    )
    .unwrap(),
    "Should allow alice (doesn't match any)"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "username": "bob"
          }
      })
    )
    .unwrap(),
    "Should allow bob (doesn't match any)"
  );
}

#[test]
fn date_not_equals_with_array() {
  // Test DateNotEquals with array
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::bucket/*",
          "Condition": {
              "DateNotEquals": {
                  "aws:CurrentTime": [
                      "2025-12-25T00:00:00Z",
                      "2025-12-31T00:00:00Z",
                      "2026-01-01T00:00:00Z"
                  ]
              }
          }
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Forbidden dates should be DENIED
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "CurrentTime": "2025-12-25T00:00:00Z"
          }
      })
    )
    .unwrap(),
    "Should deny 2025-12-25 (equals item in list)"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "CurrentTime": "2025-12-31T00:00:00Z"
          }
      })
    )
    .unwrap(),
    "Should deny 2025-12-31 (equals item in list)"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "CurrentTime": "2026-01-01T00:00:00Z"
          }
      })
    )
    .unwrap(),
    "Should deny 2026-01-01 (equals item in list)"
  );

  // Non-forbidden dates should be ALLOWED
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "CurrentTime": "2025-06-15T12:00:00Z"
          }
      })
    )
    .unwrap(),
    "Should allow 2025-06-15 (doesn't match any)"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "CurrentTime": "2025-12-31T00:00:00Z"
          }
      })
    )
    .unwrap(),
    "Should deny 2025-12-31 (New Year's Eve - in forbidden list)"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "CurrentTime": "2026-01-01T00:00:00Z"
          }
      })
    )
    .unwrap(),
    "Should deny 2026-01-01 (New Year's Day - in forbidden list)"
  );
}

#[test]
fn string_not_like_with_array() {
  // Test StringNotLike with array
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "testuser"},
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::bucket/*",
          "Condition": {
              "StringNotLike": {
                  "aws:username": ["admin-*", "root-*", "system-*"]
              }
          }
      }]
  });

  let evaluator = compile_policy(policy).expect("Failed to compile policy");

  // Usernames matching forbidden patterns should be DENIED
  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "username": "admin-alice"
          }
      })
    )
    .unwrap(),
    "Should deny 'admin-alice' (matches admin-* pattern)"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "username": "root-user"
          }
      })
    )
    .unwrap(),
    "Should deny 'root-user' (matches root-* pattern)"
  );

  assert!(
    !evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "username": "system-daemon"
          }
      })
    )
    .unwrap(),
    "Should deny 'system-daemon' (matches system-* pattern)"
  );

  // Usernames NOT matching any pattern should be ALLOWED
  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "username": "alice"
          }
      })
    )
    .unwrap(),
    "Should allow 'alice' (doesn't match any pattern)"
  );

  assert!(
    evaluate(
      &evaluator,
      json!({
          "principal": "testuser",
          "action": "s3:GetObject",
          "resource": "arn:aws:s3:::bucket/file.txt",
          "aws": {
              "username": "bob-developer"
          }
      })
    )
    .unwrap(),
    "Should allow 'bob-developer' (doesn't match any pattern)"
  );
}
