use std::fmt::{self, Write};

use crate::{
  conditions::{Conditions, build_condition},
  emit::Emit,
  interpolation::substitute_variables,
  parser::Error,
  values::Effect,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expr {
  Statement(Effect, Vec<Expr>, Conditions),

  Call(Call),
  Var(Var),
  List(Vec<Expr>),
  AnyIn(Box<Expr>),
  Bool(bool),
  Str(Str),
  Int(i64),

  Neg(Box<Expr>),
  Eq(Box<Expr>, Box<Expr>),
  Ne(Box<Expr>, Box<Expr>),
  Gt(Box<Expr>, Box<Expr>),
  Gte(Box<Expr>, Box<Expr>),
  Lt(Box<Expr>, Box<Expr>),
  Lte(Box<Expr>, Box<Expr>),

  Every(Box<Expr>, Box<Expr>, Box<Expr>),
}

impl Expr {
  pub fn call(function: &'static str, args: Vec<Expr>) -> Expr {
    Expr::Call(Call(function, args))
  }

  pub fn var<S: AsRef<str>>(var: S) -> Expr {
    Expr::Var(Var(var.as_ref().to_string()))
  }

  pub fn id(expr: Expr) -> Expr {
    expr
  }

  pub fn neg(expr: Expr) -> Expr {
    Expr::Neg(expr.boxed())
  }

  pub fn list(list: Vec<Expr>) -> Expr {
    Expr::List(list)
  }

  pub fn bool(b: bool) -> Result<Expr, Error> {
    Ok(Expr::Bool(b))
  }

  pub fn str<S: AsRef<str>>(str: S) -> Result<Expr, Error> {
    Ok(Expr::Str(substitute_variables(str.as_ref())?))
  }

  pub fn int(i: i64) -> Result<Expr, Error> {
    Ok(Expr::Int(i))
  }

  pub fn every<F>(list: Vec<Expr>, f: F) -> Result<Expr, Error>
  where
    F: Fn(Expr) -> Result<Expr, Error>,
  {
    Ok(Expr::Every(Expr::item().boxed(), Expr::list(list).boxed(), f(Expr::item())?.boxed()))
  }

  pub fn item() -> Expr {
    Expr::var("item")
  }

  pub fn boxed(self) -> Box<Expr> {
    Box::new(self)
  }
}

pub trait Repr: fmt::Debug + Eq + PartialEq {
  fn repr(&self, buf: &mut String) -> Result<(), Error>;

  #[cfg(test)]
  fn repr_to_string(&self) -> Result<String, Error> {
    let mut s = String::new();
    self.repr(&mut s)?;
    Ok(s)
  }
}

impl Repr for Expr {
  fn repr(&self, buf: &mut String) -> Result<(), Error> {
    match self {
      #[allow(unused_must_use)]
      Expr::Statement(effect, exprs, conditions) => {
        match effect {
          Effect::Allow => buf.push_str("permit if {\n"),
          Effect::Deny => buf.push_str("deny if {\n"),
        }

        for expr in exprs {
          emit!(buf, "  ", expr, '\n');
        }

        if !conditions.is_empty() {
          for (operator, condition) in conditions {
            for cond in build_condition(operator, condition)? {
              emit!(buf, "  ", cond, '\n');
            }
          }
        }

        buf.push_str("}\n");
      }

      Expr::Call(e) => e.repr(buf)?,
      Expr::Var(e) => e.repr(buf)?,
      Expr::List(e) => e.as_slice().repr(buf)?,
      Expr::AnyIn(e) => {
        emit!(buf, e, "[_]");
      }
      Expr::Bool(e) => write!(buf, "{e}")?,
      Expr::Str(e) => e.repr(buf)?,
      Expr::Int(e) => write!(buf, "{e}")?,
      Expr::Neg(e) => {
        emit!(buf, "not ", e);
      }
      Expr::Eq(lhs, rhs) => {
        emit!(buf, lhs, " == ", rhs);
      }
      Expr::Ne(lhs, rhs) => {
        emit!(buf, lhs, " != ", rhs);
      }
      Expr::Gt(lhs, rhs) => {
        emit!(buf, lhs, " > ", rhs);
      }
      Expr::Gte(lhs, rhs) => {
        emit!(buf, lhs, " >= ", rhs);
      }
      Expr::Lt(lhs, rhs) => {
        emit!(buf, lhs, " < ", rhs);
      }
      Expr::Lte(lhs, rhs) => {
        emit!(buf, lhs, " <= ", rhs);
      }
      Expr::Every(var, lhs, rhs) => {
        emit!(buf, "every ", var, " in ", lhs, " { ", rhs, " }");
      }
    }

    Ok(())
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Str {
  Plain(String),
  Template(String, Vec<Expr>),
}

impl Str {
  pub fn literal<S: AsRef<str>>(lit: S) -> Str {
    Str::Plain(lit.as_ref().to_string())
  }

  pub fn tmpl<S: AsRef<str>>(lit: S, args: Vec<Expr>) -> Str {
    Str::Template(lit.as_ref().to_string(), args)
  }
}

impl From<String> for Str {
  fn from(value: String) -> Self {
    substitute_variables(&value).unwrap()
  }
}

impl Repr for Str {
  fn repr(&self, buf: &mut String) -> Result<(), Error> {
    match self {
      Str::Plain(s) => write!(buf, r#""{s}""#)?,
      Str::Template(t, vars) => {
        emit!(buf, "sprintf(", Expr::Str(Str::literal(t)), ", ", vars.as_slice(), ")");
      }
    }

    Ok(())
  }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Var(pub String);

impl Repr for Var {
  fn repr(&self, buf: &mut String) -> Result<(), Error> {
    buf.push_str(&self.0);
    Ok(())
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Call(pub &'static str, pub Vec<Expr>);

impl Repr for Call {
  fn repr(&self, buf: &mut String) -> Result<(), Error> {
    buf.push_str(self.0);
    buf.push('(');

    for (i, arg) in self.1.iter().enumerate() {
      if i > 0 {
        buf.push_str(", ");
      }
      arg.repr(buf)?;
    }

    buf.push(')');

    Ok(())
  }
}

impl<T: Repr> Repr for &[T] {
  fn repr(&self, buf: &mut String) -> Result<(), Error> {
    buf.push('[');

    for (i, item) in self.iter().enumerate() {
      if i > 0 {
        buf.push_str(", ");
      }
      item.repr(buf)?;
    }

    buf.push(']');

    Ok(())
  }
}
