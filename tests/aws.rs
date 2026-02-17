mod helpers;

use serde_json::json;

use crate::helpers::{compile_policy, evaluate, input};

// Collection of tests from:
//  - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html
//  - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-logic-multiple-context-keys-or-values.html

#[test]
fn for_all_values_negative_1() {
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": "*",
          "Action": "*",
          "Resource": "*",
        },
        {
          "Effect": "Deny",
          "Principal": "*",
          "Action": "*",
          "Resource": "*",
          "Condition": {
              "ForAllValues:StringNotLike": {
                  "aws:TagKeys": ["key1*"]
              }
          }
        },
      ]
  });

  let evaluator = compile_policy(policy);

  eprintln!("{}", evaluator);

  let req = input(json!({ "TagKeys": "key1:legal" }));
  assert_eq!(evaluate(&evaluator, req), true);

  let req = input(json!({ "TagKeys": ["key1:legal"] }));
  assert_eq!(evaluate(&evaluator, req), true);

  let req = input(json!({ "TagKeys": ["key1:hr", "key1:personnel"] }));
  assert_eq!(evaluate(&evaluator, req), true);

  let req = input(json!({ "TagKeys": ["key2:audit"] }));
  assert_eq!(evaluate(&evaluator, req), false);

  let req = input(json!({}));
  assert_eq!(evaluate(&evaluator, req), false);
}

#[test]
fn for_all_values_negative_2() {
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": "*",
          "Action": "*",
          "Resource": "*",
        },
        {
          "Effect": "Deny",
          "Principal": "*",
          "Action": "*",
          "Resource": "*",
          "Condition": {
              "ForAllValues:StringNotLike": {
                  "aws:TagKeys": ["key1*", "key2*"]
              }
          }
        },
      ]
  });

  let evaluator = compile_policy(policy);

  let req = input(json!({ "TagKeys": "key1:legal" }));
  assert_eq!(evaluate(&evaluator, req), true);

  let req = input(json!({ "TagKeys": ["key1:hr", "key1:personnel"] }));
  assert_eq!(evaluate(&evaluator, req), true);

  let req = input(json!({ "TagKeys": ["key1:hr", "key2:audit"] }));
  assert_eq!(evaluate(&evaluator, req), true);

  let req = input(json!({ "TagKeys": ["key3:legal"] }));
  assert_eq!(evaluate(&evaluator, req), false);

  let req = input(json!({}));
  assert_eq!(evaluate(&evaluator, req), false);
}

#[test]
fn for_any_value_1() {
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": "*",
          "Action": "*",
          "Resource": "*",
        },
        {
          "Effect": "Deny",
          "Principal": "*",
          "Action": "*",
          "Resource": "*",
          "Condition": {
              "ForAnyValue:StringEquals": {
                  "aws:TagKeys": ["webserver"]
              }
          }
        },
      ]
  });

  let evaluator = compile_policy(policy);

  let req = input(json!({ "TagKeys": "webserver" }));
  assert_eq!(evaluate(&evaluator, req), false);

  let req = input(json!({ "TagKeys": ["environment", "webserver", "test"] }));
  assert_eq!(evaluate(&evaluator, req), false);

  let req = input(json!({ "TagKeys": ["environment", "test"] }));
  assert_eq!(evaluate(&evaluator, req), true);

  let req = input(json!({}));
  assert_eq!(evaluate(&evaluator, req), true);
}

#[test]
fn for_any_value_2() {
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": "*",
          "Action": "*",
          "Resource": "*",
        },
        {
          "Effect": "Deny",
          "Principal": "*",
          "Action": "*",
          "Resource": "*",
          "Condition": {
              "ForAnyValue:StringEquals": {
                  "aws:TagKeys": ["environment", "cost-center"]
              }
          }
        },
      ]
  });

  let evaluator = compile_policy(policy);

  let req = input(json!({ "TagKeys": "environment" }));
  assert_eq!(evaluate(&evaluator, req), false);

  let req = input(json!({ "TagKeys": ["cost-center"] }));
  assert_eq!(evaluate(&evaluator, req), false);

  let req = input(json!({ "TagKeys": ["environment", "cost-center"] }));
  assert_eq!(evaluate(&evaluator, req), false);

  let req = input(json!({ "TagKeys": ["environment", "dept"] }));
  assert_eq!(evaluate(&evaluator, req), false);

  let req = input(json!({ "TagKeys": ["dept"] }));
  assert_eq!(evaluate(&evaluator, req), true);

  let req = input(json!({}));
  assert_eq!(evaluate(&evaluator, req), true);
}

#[test]
fn for_all_values_not_commutative() {
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": "*",
          "Action": "*",
          "Resource": "*",
        },
        {
          "Effect": "Deny",
          "Principal": "*",
          "Action": "*",
          "Resource": "*",
          "Condition": {
              "ForAllValues:NumericGreaterThan": {
                  "aws:TagKeys": [10, 11, 12]
              }
          }
        },
      ]
  });

  let evaluator = compile_policy(policy);

  let req = input(json!({ "TagKeys": [13, 9] }));
  assert_eq!(evaluate(&evaluator, req), true);

  let req = input(json!({ "TagKeys": [13, 14, 15] }));
  assert_eq!(evaluate(&evaluator, req), false);
}

#[test]
fn for_any_values_not_commutative() {
  let policy = json!({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": "*",
          "Action": "*",
          "Resource": "*",
        },
        {
          "Effect": "Deny",
          "Principal": "*",
          "Action": "*",
          "Resource": "*",
          "Condition": {
              "ForAnyValue:NumericGreaterThan": {
                  "aws:TagKeys": [10, 11, 12]
              }
          }
        },
      ]
  });

  let evaluator = compile_policy(policy);

  let req = input(json!({ "TagKeys": [13, 9] }));
  assert_eq!(evaluate(&evaluator, req), false);

  let req = input(json!({ "TagKeys": [1, 2, 3] }));
  assert_eq!(evaluate(&evaluator, req), true);
}
