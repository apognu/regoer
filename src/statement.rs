use serde::Serialize;

use crate::{
  conditions::{Conditions, IdOperatorFunc, OperatorFunc},
  expression::Expr,
  extensions::TryMapExprIter,
  functions::Func,
  parser::Error,
  values::{Effect, Scope, Value},
};

#[derive(Copy, Clone, Debug, Serialize)]
pub enum ScopeType {
  Principal,
  Action,
  Resource,
}

impl ScopeType {
  pub fn input_var(&self) -> &'static str {
    match self {
      ScopeType::Principal => "input.principal",
      ScopeType::Action => "input.action",
      ScopeType::Resource => "input.resource",
    }
  }
}

#[derive(Serialize)]
pub struct Statement {
  pub effect: Effect,
  pub principals: Scope<String>,
  pub actions: Scope<String>,
  pub resources: Scope<String>,
  pub conditions: Conditions,
}

impl Statement {
  pub fn generate(self) -> Result<Expr, Error> {
    let mut exprs = vec![];

    for (kind, scope) in [(ScopeType::Principal, self.principals), (ScopeType::Action, self.actions), (ScopeType::Resource, self.resources)] {
      let negated = matches!(scope, Scope::Not(_));

      let (op, id, scopes): (OperatorFunc, IdOperatorFunc, _) = match scope {
        Scope::Id(scopes) => (&Expr::Eq, &Expr::id, scopes),
        Scope::Not(scopes) => (&Expr::Ne, &Expr::neg, scopes),
      };

      let expr = match scopes {
        Value::One(one) if one == "*" => None,
        Value::Many(list) if list.iter().all(|id| id == "*") => None,

        Value::One(one) if one.contains('*') => Some(id(Expr::call("glob.match", vec![Expr::str(one)?, Expr::var("null"), Expr::var(kind.input_var())]))),
        Value::One(one) => Some(op(Expr::var(kind.input_var()).boxed(), Expr::str(one)?.boxed())),

        Value::Many(list) if list.iter().any(|id| id.contains('*')) => match negated {
          false => Some(id(Func::glob(Expr::AnyIn(Expr::list(list.map_expr(Expr::str)?).boxed()), Expr::var(kind.input_var())))),
          true => Some(Expr::every(list.map_expr(Expr::str)?, |e| Ok(id(Func::glob(e, Expr::var(kind.input_var())))))?),
        },
        Value::Many(list) => match negated {
          false => Some(op(Expr::AnyIn(Expr::list(list.map_expr(Expr::str)?).boxed()).boxed(), Expr::var(kind.input_var()).boxed())),
          true => Some(Expr::every(list.map_expr(Expr::str)?, |e| Ok(op(e.boxed(), Expr::var(kind.input_var()).boxed())))?),
        },
      };

      if let Some(expr) = expr {
        exprs.push(expr);
      }
    }

    Ok(Expr::Statement(self.effect, exprs, self.conditions))
  }
}
