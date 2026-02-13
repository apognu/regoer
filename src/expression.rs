use std::fmt::{self, Write};

use crate::{
  conditions::{Conditions, build_condition},
  interpolation::substitute_variables,
  parser::Error,
  values::{Effect, Value},
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
  fn repr(&self) -> Result<String, Error>;
}

impl Repr for Expr {
  fn repr(&self) -> Result<String, Error> {
    match self {
      #[allow(unused_must_use)]
      Expr::Statement(effect, exprs, conditions) => {
        let mut buf = String::new();

        match effect {
          Effect::Allow => {
            writeln!(&mut buf, "permit if {{");
          }

          Effect::Deny => {
            writeln!(&mut buf, "deny if {{");
          }
        }

        for expr in exprs {
          writeln!(&mut buf, "  {}", expr.repr()?);
        }

        if !conditions.is_empty() {
          for (operator, condition) in conditions {
            for cond in build_condition(operator, condition)? {
              writeln!(&mut buf, "  {}", cond.repr()?);
            }
          }
        }

        writeln!(buf, "}}");

        Ok(buf)
      }

      Expr::Call(e) => e.repr(),
      Expr::Var(e) => e.repr(),
      Expr::List(e) => e.as_slice().repr(),
      Expr::AnyIn(e) => Ok(format!("{}[_]", e.repr()?)),
      Expr::Bool(e) => Ok(format!("{e}")),
      Expr::Str(e) => e.repr(),
      Expr::Int(e) => Ok(format!("{e}")),
      Expr::Neg(e) => Ok(format!("not {}", e.repr()?)),
      Expr::Eq(lhs, rhs) => Ok(format!("{} == {}", lhs.repr()?, rhs.repr()?)),
      Expr::Ne(lhs, rhs) => Ok(format!("{} != {}", lhs.repr()?, rhs.repr()?)),
      Expr::Gt(lhs, rhs) => Ok(format!("{} > {}", lhs.repr()?, rhs.repr()?)),
      Expr::Gte(lhs, rhs) => Ok(format!("{} >= {}", lhs.repr()?, rhs.repr()?)),
      Expr::Lt(lhs, rhs) => Ok(format!("{} < {}", lhs.repr()?, rhs.repr()?)),
      Expr::Lte(lhs, rhs) => Ok(format!("{} <= {}", lhs.repr()?, rhs.repr()?)),
      Expr::Every(var, lhs, rhs) => Ok(format!("every {} in {} {{ {} }}", var.repr()?, lhs.repr()?, rhs.repr()?)),
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Str {
  Plain(String),
  Template(String, Vec<Expr>),
}

impl Str {
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
  fn repr(&self) -> Result<String, Error> {
    match self {
      Str::Plain(s) => Ok(format!(r#""{s}""#)),
      Str::Template(t, vars) => Ok(format!(r"sprintf({}, {})", t.as_str().repr()?, vars.as_slice().repr()?)),
    }
  }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Var(pub String);

impl Repr for Var {
  fn repr(&self) -> Result<String, Error> {
    Ok(self.0.to_string())
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Call(pub &'static str, pub Vec<Expr>);

impl Repr for Call {
  fn repr(&self) -> Result<String, Error> {
    let args = self.1.iter().try_fold(vec![], |mut acc, i| {
      acc.push(i.repr()?);
      Ok::<_, Error>(acc)
    })?;

    Ok(format!("{}({})", self.0, args.as_slice().join(", ")))
  }
}

impl<T: Repr> Repr for &[T] {
  fn repr(&self) -> Result<String, Error> {
    let list = self.iter().try_fold(vec![], |mut acc, i| {
      acc.push(i.repr()?);
      Ok::<_, Error>(acc)
    })?;

    Ok(format!(r#"[{}]"#, list.join(", ")))
  }
}

impl Repr for &str {
  fn repr(&self) -> Result<String, Error> {
    Ok(format!(r#""{}""#, self))
  }
}

impl<T> Repr for Value<T>
where
  T: Repr,
{
  fn repr(&self) -> Result<String, Error> {
    match self {
      Value::One(one) => one.repr(),
      Value::Many(list) => list.as_slice().repr(),
    }
  }
}
