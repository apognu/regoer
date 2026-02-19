use crate::expression::Expr;

pub struct Func;

impl Func {
  pub fn glob(lhs: Expr, rhs: Expr) -> Expr {
    Expr::call("glob.match", vec![lhs, Expr::var("null"), rhs])
  }

  pub fn lower(lhs: Expr) -> Expr {
    Expr::call("lower", vec![lhs])
  }

  pub fn cidr_contains(cidr: Expr, ip: Expr) -> Expr {
    Expr::call("net.cidr_contains", vec![cidr, ip])
  }

  pub fn datetime(dt: Expr) -> Expr {
    Expr::call("time.parse_rfc3339_ns", vec![dt])
  }

  pub fn arn_like(lhs: Expr, rhs: Expr) -> Expr {
    Expr::call("arn_like", vec![lhs, rhs])
  }

  pub fn to_array(expr: Expr) -> Expr {
    let path = match &expr {
      Expr::Var(v) => &v.0,
      _ => return expr,
    };

    let var = match path.rsplit_once('.') {
      Some((object, key)) => Expr::call("object.get", vec![Expr::var(object), Expr::var(format!(r#""{key}""#)), Expr::List(vec![])]),
      None => expr,
    };

    Expr::call("to_array", vec![var])
  }
}
