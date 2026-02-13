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
}
