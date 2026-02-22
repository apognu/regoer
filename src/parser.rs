use std::{fmt::Write, io};

use aws_iam::model::{Action, Effect as AwsEffect, OneOrAll, OneOrAny, Principal, QString, Resource};

use crate::{
  expression::{Expr, Repr},
  interpolation::SubstitutionError,
  statement::Statement,
  values::{Effect, Scope, Value},
};

const BASE: &str = r#"package main
default allow = false
default deny = false
default permit = false
to_array(x) := x if { is_array(x) }
to_array(x) := [x] if { not is_array(x) }
arn_like(lhs, rhs) if {
  count(indexof_n(lhs, ":")) == 5
  count(indexof_n(rhs, ":")) == 5
  glob.match(lhs, [":"], rhs)
}
allow if {
  permit
  not deny
}"#;

#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error("generic error: {0}")]
  GenericError(String),

  #[error("unsupported principal type, only 'AWS' is supported")]
  UnsupportedPrincipalType,
  #[error("unsupported wildcard")]
  UnsupportedWildcard,
  #[error("unsupported negation")]
  UnsupportedNegation,
  #[error("expected {0}, found '{1}'")]
  InvalidType(&'static str, String),
  #[error("unsupported function {0}")]
  UnsupportedFunction(String),
  #[error("invalid string interpolation: {0}")]
  InvalidStringInterpolation(#[from] SubstitutionError),

  #[error("json error: {0}")]
  JsonError(#[from] serde_json::Error),
  #[error("I/O error: {0:?}")]
  PolicyError(aws_iam::io::Error),
  #[error("formatting error: {0}")]
  FmtError(#[from] std::fmt::Error),
}

/// Internal AST for an IAM policy.
#[derive(Clone, Debug)]
pub struct Policy(pub(crate) Vec<Expr>);

impl Policy {
  /// Serialize the parsed policy to Rego
  pub fn serialize(&self) -> Result<String, Error> {
    let mut buf = String::with_capacity(1024);

    writeln!(buf, "{}", BASE)?;

    for statement in &self.0 {
      statement.repr(&mut buf)?;
    }

    Ok(buf)
  }
}

pub fn parse_iam_policy<R>(reader: R) -> Result<Policy, Error>
where
  R: io::Read,
{
  let statements = aws_iam::io::read_from_reader(reader).map_err(Error::PolicyError)?;
  let mut out = vec![];

  for statement in statements.statement.all().unwrap_or_default() {
    let effect = match statement.effect {
      AwsEffect::Allow => Effect::Allow,
      AwsEffect::Deny => Effect::Deny,
    };

    let principals = match statement.principal {
      None => Value::One("*".into()).into(),
      Some(p) => match p {
        Principal::Principal(p) => match p.get(&aws_iam::model::PrincipalType::AWS).unwrap() {
          OneOrAny::AnyOf(list) => Value::Many(list.clone()).into(),
          OneOrAny::One(one) => Value::One(one.to_string()).into(),
          OneOrAny::Any => Err(Error::UnsupportedPrincipalType)?,
        },

        Principal::NotPrincipal(_) => Err(Error::UnsupportedNegation)?,
      },
    };

    let actions = match statement.action {
      Action::Action(a) => match a {
        OneOrAny::AnyOf(list) => Value::Many(list.iter().map(QString::to_string).collect()).into(),
        OneOrAny::One(one) => Value::One(one.to_string()).into(),
        OneOrAny::Any => Err(Error::UnsupportedWildcard)?,
      },

      Action::NotAction(a) => match a {
        OneOrAny::AnyOf(list) => Scope::Not(Value::Many(list.iter().map(QString::to_string).collect())),
        OneOrAny::One(one) => Scope::Not(Value::One(one.to_string())),
        OneOrAny::Any => Err(Error::UnsupportedWildcard)?,
      },
    };

    let resources = match statement.resource {
      Resource::Resource(r) => match r {
        OneOrAny::AnyOf(list) => Value::Many(list).into(),
        OneOrAny::One(one) => Value::One(one).into(),
        OneOrAny::Any => Err(Error::UnsupportedWildcard)?,
      },

      Resource::NotResource(a) => match a {
        OneOrAny::AnyOf(list) => Scope::Not(Value::Many(list)),
        OneOrAny::One(one) => Scope::Not(Value::One(one)),
        OneOrAny::Any => Err(Error::UnsupportedWildcard)?,
      },
    };

    let mut conditions = vec![];

    for (operator, vars) in statement.condition.unwrap_or_default() {
      let mut attributes = vec![];

      for (attribute, condition) in vars {
        match condition {
          OneOrAll::All(list) => attributes.push((attribute, Value::Many(list.into_iter().map(Into::into).collect()))),
          OneOrAll::One(one) => {
            attributes.push((attribute, Value::One(one.into())));
          }
        }
      }

      conditions.push((operator, attributes));
    }

    let s = Statement {
      effect,
      principals,
      actions,
      resources,
      conditions,
    };

    out.push(s.generate()?);
  }

  Ok(Policy(out))
}
