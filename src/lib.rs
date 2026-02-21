#![doc = include_str!("../README.md")]

mod conditions;
mod expression;
mod extensions;
mod functions;
mod interpolation;
mod parser;
mod statement;
mod values;

use std::{fmt, io, sync::Arc};

use regorus::{CompiledPolicy, Engine};
use serde::Serialize;

pub use crate::parser::{Error, Policy};

/// AWS IAM policy parser
///
/// This is the entrypoint of the library, you should use this to parse an
/// initial IAM policy and build an internal AST representing it.
///
/// It does not allow for the policies to be evaluated, yet, allowing you
/// to add multiple policies to be merged later on.
///
/// When ready, you can call [`Regoer::compile()`](Self::compile()) to obtain the evaluator.
///
/// ## Example
///
/// ```rust
/// # use std::io::BufReader;
/// # use regoer::Regoer;
/// #
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let iam = BufReader::new(r#"
///   {
///     "Version": "2012-10-17",
///     "Statement": [
///       {
///         "Sid": "Sid1",
///         "Effect": "Allow",
///         "Principal": { "AWS": "apognu" },
///         "Action": ["s3:Get*"],
///         "Resource": "arn:aws:s3:::public/*.jpg"
///       }
///     ]
///   }
/// "#.as_bytes());
///
/// let mut regoer = Regoer::default();
/// regoer.add_policy(iam)?;
/// let evaluator = regoer.compile()?;
///
/// # Ok(())
/// # }
/// ```
pub struct Regoer {
  engine: Engine,
  policies: Vec<Policy>,
}

/// Collection of [`Policy`] to be evaluated.
///
/// Can be build by calling [`Regoer::compile()`].
pub struct Evaluator {
  policy: CompiledPolicy,
  policies: Vec<Policy>,
}

impl Default for Regoer {
  fn default() -> Self {
    Self {
      engine: Engine::new(),
      policies: vec![],
    }
  }
}

impl Regoer {
  /// Appends a policy to the evaluator
  ///
  /// An arbitrary number of policies can be added to [`Regoer`], they will all
  /// be concatenated and used to drive decisions.
  ///
  /// This method accepts any item implementing [`io::Read`].
  pub fn add_policy<R>(&mut self, input: R) -> Result<(), Error>
  where
    R: io::Read,
  {
    let policy = parser::parse_iam_policy(input)?;

    self.policies.push(policy);

    Ok(())
  }

  /// Adds static data used across decisions.
  ///
  /// Only common data should be added here, since the same set will be used for
  /// all decisions drive by this policy.
  ///
  /// Request-specific data will be provided at the time of evaluation.
  ///
  /// The data provided should implement [`serde::Serialize`] since it it provided
  /// to the engine as a [`serde_json::Value`].
  pub fn add_data(&mut self, data: impl Serialize) -> Result<(), Error> {
    let data: serde_json::Value = serde_json::to_value(&data).map_err(|err| Error::GenericError(err.to_string()))?;

    self.engine.add_data(data.into()).map_err(|err| Error::GenericError(err.to_string()))
  }

  /// Compiles the added policies into an [`Evaluator`].
  ///
  /// This consumes the [`Regoer`] builder so it cannot be used anymore. If
  /// you need to build a new set of policies, create a new instance of
  /// [`Regoer`].
  pub fn compile(mut self) -> Result<Evaluator, Error> {
    for policy in &self.policies {
      self.engine.add_policy("main.rego".into(), policy.serialize()?).map_err(|err| Error::GenericError(err.to_string()))?;
    }

    let policy = self.engine.compile_with_entrypoint(&Arc::from("data.main.allow")).unwrap();

    Ok(Evaluator { policies: self.policies, policy })
  }
}

impl Evaluator {
  /// Evaluates the policy set.
  ///
  /// Run all the policies that were compiled into this evaluator, returning
  /// a boolean on whether the request should be accepted or not.
  ///
  /// It takes an object that implements [`Serialize`] and that takes the following
  /// shape:
  ///
  /// ```rust
  /// # use serde_json::json;
  ///
  /// let input = json!({
  ///   "principal": "apognu",
  ///   "action": "s3:GetObject",
  ///   "resource": "arn:aws:s3:::bucket/object"
  /// });
  /// ```
  ///
  /// Apart from `principal`, `action` and `resource`, this object is freeform, but
  /// should match what is expected from the compiled policies.
  pub fn evaluate(&self, input: &impl Serialize) -> Result<bool, Error> {
    let input: serde_json::Value = serde_json::to_value(&input).map_err(|err| Error::GenericError(err.to_string()))?;
    let result = self.policy.eval_with_input(input.into()).map_err(|err| Error::GenericError(err.to_string()))?;

    result.as_bool().copied().map_err(|err| Error::GenericError(err.to_string()))
  }

  /// Get the policies compiled into this evaluator.
  pub fn rego(&self) -> &[Policy] {
    &self.policies
  }
}

impl fmt::Display for Evaluator {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for policy in &self.policies {
      match policy.serialize() {
        Ok(output) => write!(f, "{}", output)?,
        Err(err) => write!(f, "// ERROR: {}", err)?,
      }
    }

    Ok(())
  }
}
