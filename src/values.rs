use std::ops::{Deref, DerefMut};

use serde::Serialize;

use crate::parser::Error;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
pub enum Effect {
  Allow,
  Deny,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub enum Value<T> {
  One(T),
  Many(Vec<T>),
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub enum Scope<T> {
  Id(Value<T>),
  Not(Value<T>),
}

impl<T> From<Value<T>> for Scope<T> {
  fn from(value: Value<T>) -> Self {
    Scope::Id(value)
  }
}

impl<T> Deref for Scope<T> {
  type Target = Value<T>;

  fn deref(&self) -> &Self::Target {
    match self {
      Scope::Id(s) => s,
      Scope::Not(s) => s,
    }
  }
}

impl<T> DerefMut for Scope<T> {
  fn deref_mut(&mut self) -> &mut Self::Target {
    match self {
      Scope::Id(s) => &mut *s,
      Scope::Not(s) => &mut *s,
    }
  }
}

impl<T> Value<T> {
  pub fn map<F, O>(&self, mut f: F) -> Result<Value<O>, Error>
  where
    F: FnMut(&T) -> Result<O, Error>,
  {
    match self {
      Value::One(one) => Ok(Value::One(f(one)?)),

      Value::Many(list) => Ok(Value::Many(list.iter().try_fold(Vec::with_capacity(list.len()), |mut acc, item| {
        acc.push(f(item)?);

        Ok::<_, Error>(acc)
      })?)),
    }
  }
}

#[derive(Clone, Debug, Serialize)]
pub struct ConditionValue(pub aws_iam::model::ConditionValue);

impl PartialEq for ConditionValue {
  fn eq(&self, other: &Self) -> bool {
    use aws_iam::model::ConditionValue::*;

    match (&self.0, &other.0) {
      (String(a), String(b)) => a == b,
      (Integer(a), Integer(b)) => a == b,
      (Float(a), Float(b)) => a == b,
      (Bool(a), Bool(b)) => a == b,
      _ => false,
    }
  }
}

impl Eq for ConditionValue {}

impl From<aws_iam::model::ConditionValue> for ConditionValue {
  fn from(value: aws_iam::model::ConditionValue) -> Self {
    ConditionValue(value)
  }
}

impl Deref for ConditionValue {
  type Target = aws_iam::model::ConditionValue;

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}
