use std::{env, error::Error, fs::OpenOptions};

use regoer::Regoer;
use serde::Serialize;
use serde_json::json;

#[derive(Serialize)]
struct Input {
  principal: &'static str,
  action: &'static str,
  resource: &'static str,
  aws: serde_json::Value,
}

fn main() -> Result<(), Box<dyn Error>> {
  let mut regoer = Regoer::default();

  let f = OpenOptions::new().read(true).open(env::args().nth(1).unwrap())?;
  regoer.add_policy(f)?;

  let evaluator = regoer.compile()?;

  for policy in evaluator.rego() {
    println!("{}", policy.serialize()?);
  }

  let input = Input {
    principal: "apognu",
    action: "s3:GetObject",
    resource: "arn:aws:s3:::public/apognu/image.jpg",
    aws: json!({
      "PrincipalType": "AssumedRole",
      "CurrentTime": "2026-02-15T22:46:30Z",
      "userid": "apognu",
      "SourceIp": "10.12.13.14",
      "BucketTag": {
        "env": "staging",
      },
      "BucketAlias": ["delivery", "cdn", "files"],
    }),
  };

  let allowed = evaluator.evaluate(&input)?;

  println!("allowed = {allowed}");

  Ok(())
}
