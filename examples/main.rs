use std::{collections::HashMap, env, error::Error, fs::OpenOptions};

use regoer::Regoer;
use serde::Serialize;

#[derive(Serialize)]
struct Input {
  principal: &'static str,
  action: &'static str,
  resource: &'static str,
  aws: AwsVariables,
}

#[derive(Serialize)]
struct AwsVariables {
  #[serde(rename = "PrincipalType")]
  principal_type: &'static str,
  #[serde(rename = "CurrentTime")]
  current_time: &'static str,
  userid: &'static str,
  #[serde(rename = "SourceIp")]
  source_ip: &'static str,
  #[serde(rename = "BucketTag")]
  bucket_tag: HashMap<&'static str, &'static str>,
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
    aws: AwsVariables {
      principal_type: "AssumedRole",
      current_time: "2026-02-15T22:46:30Z",
      userid: "apognu",
      source_ip: "10.12.13.14",
      bucket_tag: {
        let mut map = HashMap::default();
        map.insert("env", "staging");
        map
      },
    },
  };

  let allowed = evaluator.evaluate(input)?;

  println!("allowed = {allowed}");

  Ok(())
}
