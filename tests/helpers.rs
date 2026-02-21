#![allow(unused)]

use regoer::{Error, Regoer};
use serde_json::json;

pub fn compile_policy(policy_json: serde_json::Value) -> regoer::Evaluator {
  let mut regoer = Regoer::default();
  let policy_str = serde_json::to_string(&policy_json).unwrap();
  regoer.add_policy(policy_str.as_bytes()).unwrap();
  regoer.compile().unwrap()
}

pub fn evaluate(evaluator: &regoer::Evaluator, input: serde_json::Value) -> bool {
  evaluator.evaluate(&input).unwrap()
}

pub fn input(attrs: serde_json::Value) -> serde_json::Value {
  json!({
      "principal": "anyuser",
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::test-bucket/test-file.txt",
      "aws": attrs,
  })
}
