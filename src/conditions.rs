use std::str::FromStr;

use aws_iam::model::QString;

use crate::{
  expression::Expr,
  extensions::TryMapExprIter,
  functions::Func,
  parser::Error,
  values::{ConditionValue, Value},
};

pub type Conditions = Vec<(String, Vec<CondPair>)>;
pub type CondPair = (QString, Value<ConditionValue>);
pub type OperatorFunc<'f> = &'f dyn Fn(Box<Expr>, Box<Expr>) -> Expr;
pub type IdOperatorFunc<'f> = &'f dyn Fn(Expr) -> Expr;

enum Operator {
  Bool,
  StringEquals,
  StringNotEquals,
  StringEqualsIgnoreCase,
  StringNotEqualsIgnoreCase,
  StringLike,
  StringNotLike,
  NumericEquals,
  NumericNotEquals,
  NumericLessThan,
  NumericLessThanEquals,
  NumericGreaterThan,
  NumericGreaterThanEquals,
  DateEquals,
  DateNotEquals,
  DateGreaterThan,
  DateGreaterThanEquals,
  DateLessThan,
  DateLessThanEquals,
  IpAddress,
  NotIpAddress,
}

impl FromStr for Operator {
  type Err = Error;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    use Operator::*;

    Ok(match s {
      "Bool" => Bool,
      "StringEquals" => StringEquals,
      "StringNotEquals" => StringNotEquals,
      "StringEqualsIgnoreCase" => StringEqualsIgnoreCase,
      "StringNotEqualsIgnoreCase" => StringNotEqualsIgnoreCase,
      "StringLike" => StringLike,
      "StringNotLike" => StringNotLike,
      "NumericEquals" => NumericEquals,
      "NumericNotEquals" => NumericNotEquals,
      "NumericLessThan" => NumericLessThan,
      "NumericLessThanEquals" => NumericLessThanEquals,
      "NumericGreaterThan" => NumericGreaterThan,
      "NumericGreaterThanEquals" => NumericGreaterThanEquals,
      "DateEquals" => DateEquals,
      "DateNotEquals" => DateNotEquals,
      "DateGreaterThan" => DateGreaterThan,
      "DateGreaterThanEquals" => DateGreaterThanEquals,
      "DateLessThan" => DateLessThan,
      "DateLessThanEquals" => DateLessThanEquals,
      "IpAddress" => IpAddress,
      "NotIpAddress" => NotIpAddress,
      _ => Err(Error::UnsupportedFunction(s.to_string()))?,
    })
  }
}

impl Operator {
  fn is_neg(&self) -> bool {
    matches!(
      self,
      Self::StringNotEquals | Self::StringNotEqualsIgnoreCase | Self::NumericNotEquals | Self::StringNotLike | Self::NotIpAddress | Self::DateNotEquals
    )
  }
}

pub fn build_condition(operator: &str, condition: &[CondPair]) -> Result<Vec<Expr>, Error> {
  use Operator::*;

  match Operator::from_str(operator)? {
    Bool => condition.iter().try_fold(vec![], |mut acc, (attr, values)| {
      acc.push(match values.map(to_bool)? {
        Value::One(one) => Expr::Eq(resolve(attr)?.boxed(), Expr::bool(one)?.boxed()),
        Value::Many(list) => Expr::Eq(Expr::AnyIn(Expr::list(list.map_expr(Expr::bool)?).boxed()).boxed(), resolve(attr)?.boxed()),
      });

      Ok::<_, Error>(acc)
    }),

    op @ StringEquals => compare_strings(op, condition),
    op @ StringNotEquals => compare_strings(op, condition),
    op @ StringEqualsIgnoreCase => compare_strings_nocase(op, condition),
    op @ StringNotEqualsIgnoreCase => compare_strings_nocase(op, condition),
    op @ StringLike => compare_strings_like(op, condition),
    op @ StringNotLike => compare_strings_like(op, condition),

    NumericEquals => compare_numbers(Expr::Eq, condition),
    op @ NumericNotEquals => compare_numbers_id(op, condition),
    NumericLessThan => compare_numbers(Expr::Lt, condition),
    NumericLessThanEquals => compare_numbers(Expr::Lte, condition),
    NumericGreaterThan => compare_numbers(Expr::Gt, condition),
    NumericGreaterThanEquals => compare_numbers(Expr::Gte, condition),

    DateEquals => compare_datetimes(Expr::Eq, condition),
    op @ DateNotEquals => compare_datetimes_id(op, condition),
    DateGreaterThan => compare_datetimes(Expr::Gt, condition),
    DateGreaterThanEquals => compare_datetimes(Expr::Gte, condition),
    DateLessThan => compare_datetimes(Expr::Lt, condition),
    DateLessThanEquals => compare_datetimes(Expr::Lte, condition),

    op @ IpAddress => compare_ips(op, condition),
    op @ NotIpAddress => compare_ips(op, condition),
  }
}

fn compare_strings(operator: Operator, condition: &[(QString, Value<ConditionValue>)]) -> Result<Vec<Expr>, Error> {
  let op = if operator.is_neg() { Expr::Ne } else { Expr::Eq };

  condition.iter().try_fold(vec![], |mut acc, (attr, values)| {
    acc.push(match values.map(to_str)? {
      Value::One(one) => op(resolve(attr)?.boxed(), Expr::str(one)?.boxed()),
      Value::Many(list) => match operator.is_neg() {
        false => op(Expr::AnyIn(Expr::list(list.map_expr(Expr::str)?).boxed()).boxed(), resolve(attr)?.boxed()),
        true => Expr::every(list.map_expr(Expr::str)?, |e| Ok(op(resolve(attr)?.boxed(), e.boxed())))?,
      },
    });

    Ok::<_, Error>(acc)
  })
}

fn compare_strings_nocase(operator: Operator, condition: &[(QString, Value<ConditionValue>)]) -> Result<Vec<Expr>, Error> {
  let op = if operator.is_neg() { Expr::Ne } else { Expr::Eq };

  condition.iter().try_fold(vec![], |mut acc, (attr, values)| {
    acc.push(match values.map(to_str)? {
      Value::One(one) => op(Func::lower(resolve(attr)?).boxed(), Func::lower(Expr::str(one)?).boxed()),
      Value::Many(list) => match operator.is_neg() {
        false => op(Func::lower(Expr::AnyIn(Expr::list(list.map_expr(Expr::str)?).boxed())).boxed(), Func::lower(resolve(attr)?).boxed()),
        true => Expr::every(list.map_expr(Expr::str)?, |e| Ok(op(Func::lower(resolve(attr)?).boxed(), Func::lower(e).boxed())))?,
      },
    });

    Ok::<_, Error>(acc)
  })
}

fn compare_strings_like(operator: Operator, condition: &[(QString, Value<ConditionValue>)]) -> Result<Vec<Expr>, Error> {
  let op = if operator.is_neg() { Expr::neg } else { Expr::id };

  condition.iter().try_fold(vec![], |mut acc, (attr, values)| {
    acc.push(match values.map(to_str)? {
      Value::One(one) => op(Func::glob(Expr::str(one)?, resolve(attr)?)),
      Value::Many(list) => match operator.is_neg() {
        false => op(Func::glob(Expr::AnyIn(Expr::list(list.map_expr(Expr::str)?).boxed()), resolve(attr)?)),
        true => Expr::every(list.map_expr(Expr::str)?, |e| Ok(op(Func::glob(e, resolve(attr)?))))?,
      },
    });

    Ok::<_, Error>(acc)
  })
}

fn compare_numbers_id(operator: Operator, condition: &[(QString, Value<ConditionValue>)]) -> Result<Vec<Expr>, Error> {
  let op = if operator.is_neg() { Expr::Ne } else { Expr::Eq };

  condition.iter().try_fold(vec![], |mut acc, (attr, values)| {
    acc.push(match values.map(to_int)? {
      Value::One(one) => op(resolve(attr)?.boxed(), Expr::Int(one).boxed()),
      Value::Many(list) => match operator.is_neg() {
        false => op(Expr::AnyIn(Expr::list(list.map_expr(Expr::int)?).boxed()).boxed(), resolve(attr)?.boxed()),
        true => Expr::every(list.map_expr(Expr::int)?, |e| Ok(op(resolve(attr)?.boxed(), e.boxed())))?,
      },
    });

    Ok::<_, Error>(acc)
  })
}

fn compare_numbers<O>(op: O, condition: &[(QString, Value<ConditionValue>)]) -> Result<Vec<Expr>, Error>
where
  O: Fn(Box<Expr>, Box<Expr>) -> Expr,
{
  condition.iter().try_fold(vec![], |mut acc, (attr, values)| {
    acc.push(match values.map(to_int)? {
      Value::One(one) => op(resolve(attr)?.boxed(), Expr::Int(one).boxed()),
      Value::Many(list) => op(Expr::AnyIn(Expr::list(list.map_expr(Expr::int)?).boxed()).boxed(), resolve(attr)?.boxed()),
    });

    Ok::<_, Error>(acc)
  })
}

fn compare_datetimes_id(operator: Operator, condition: &[(QString, Value<ConditionValue>)]) -> Result<Vec<Expr>, Error> {
  let op = if operator.is_neg() { Expr::Ne } else { Expr::Eq };

  condition.iter().try_fold(vec![], |mut acc, (attr, values)| {
    acc.push(match values.map(to_str)? {
      Value::One(one) => op(Func::datetime(resolve(attr)?).boxed(), Func::datetime(Expr::str(one)?).boxed()),
      Value::Many(list) => match operator.is_neg() {
        false => op(
          Func::datetime(Expr::AnyIn(Expr::list(list.map_expr(Expr::str)?).boxed())).boxed(),
          Func::datetime(resolve(attr)?).boxed(),
        ),
        true => Expr::every(list.map_expr(Expr::str)?, |e| Ok(op(Func::datetime(resolve(attr)?).boxed(), Func::datetime(e).boxed())))?,
      },
    });

    Ok::<_, Error>(acc)
  })
}

fn compare_datetimes<O>(op: O, condition: &[(QString, Value<ConditionValue>)]) -> Result<Vec<Expr>, Error>
where
  O: Fn(Box<Expr>, Box<Expr>) -> Expr,
{
  condition.iter().try_fold(vec![], |mut acc, (attr, values)| {
    acc.push(match values.map(to_str)? {
      Value::One(one) => op(Func::datetime(resolve(attr)?).boxed(), Func::datetime(Expr::str(one)?).boxed()),
      Value::Many(list) => op(
        Func::datetime(Expr::AnyIn(Expr::list(list.map_expr(Expr::str)?).boxed())).boxed(),
        Func::datetime(resolve(attr)?).boxed(),
      ),
    });

    Ok::<_, Error>(acc)
  })
}

fn compare_ips(operator: Operator, condition: &[(QString, Value<ConditionValue>)]) -> Result<Vec<Expr>, Error> {
  let op = if operator.is_neg() { Expr::neg } else { Expr::id };

  condition.iter().try_fold(vec![], |mut acc, (attr, values)| {
    acc.push(match values.map(to_str)? {
      Value::One(one) => op(Func::cidr_contains(Expr::str(one)?, resolve(attr)?)),
      Value::Many(list) => match operator.is_neg() {
        false => op(Func::cidr_contains(Expr::AnyIn(Expr::list(list.map_expr(Expr::str)?).boxed()), resolve(attr)?)),
        true => Expr::every(list.map_expr(Expr::str)?, |e| Ok(op(Func::cidr_contains(e, resolve(attr)?))))?,
      },
    });

    Ok::<_, Error>(acc)
  })
}

fn to_bool(s: &ConditionValue) -> Result<bool, Error> {
  use aws_iam::model::ConditionValue::*;

  Ok(match &**s {
    Bool(b) => *b,
    String(s) if s == "true" => true,
    String(s) if s == "false" => false,
    _ => Err(Error::InvalidType("bool", format!("{s:?}")))?,
  })
}

fn to_str(s: &ConditionValue) -> Result<String, Error> {
  use aws_iam::model::ConditionValue::*;

  Ok(match &**s {
    String(s) => s.to_string(),
    _ => Err(Error::InvalidType("string", format!("{s:?}")))?,
  })
}

fn to_int(s: &ConditionValue) -> Result<i64, Error> {
  use aws_iam::model::ConditionValue::*;

  Ok(match &**s {
    Integer(i) => *i,
    String(s) => s.parse().map_err(|_| Error::InvalidType("integer", s.to_string()))?,
    _ => Err(Error::InvalidType("integer", format!("{s:?}")))?,
  })
}

fn resolve(var: &QString) -> Result<Expr, Error> {
  Ok(match var.qualifier() {
    Some(q) => Expr::var(format!("input.{}.{}", q, var.value().replace('/', "."))),
    _ => Expr::var(format!("input.{}", var.to_string().replace('/', "."))),
  })
}

#[cfg(test)]
mod tests {
  use aws_iam::model::{ConditionValue as V, QString};

  use crate::{
    conditions::build_condition,
    expression::{Expr, Repr},
    values::{ConditionValue, Value},
  };

  #[test]
  fn bool_equals() {
    let expr = build_condition("Bool", &[(QString::unqualified("username".into()), Value::One(ConditionValue(V::Bool(true))))]).unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"input.username == true"#);

    let expr = build_condition(
      "Bool",
      &[(
        QString::unqualified("username".into()),
        Value::Many(vec![ConditionValue(V::Bool(true)), ConditionValue(V::Bool(false))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"[true, false][_] == input.username"#);
  }

  #[test]
  fn string_equals() {
    let expr = build_condition("StringEquals", &[(QString::unqualified("username".into()), Value::One(ConditionValue(V::String("apognu".into()))))]).unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"input.username == "apognu""#);

    let expr = build_condition(
      "StringEquals",
      &[(
        QString::unqualified("username".into()),
        Value::Many(vec![ConditionValue(V::String("apognu".into())), ConditionValue(V::String("bob".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"["apognu", "bob"][_] == input.username"#);
  }

  #[test]
  fn string_like() {
    let expr = build_condition("StringLike", &[(QString::unqualified("username".into()), Value::One(ConditionValue(V::String("apognu".into()))))]).unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"glob.match("apognu", null, input.username)"#);

    let expr = build_condition(
      "StringLike",
      &[(
        QString::unqualified("username".into()),
        Value::Many(vec![ConditionValue(V::String("apognu".into())), ConditionValue(V::String("bob".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"glob.match(["apognu", "bob"][_], null, input.username)"#);
  }

  #[test]
  fn conversions() {
    assert_eq!(super::to_bool(&ConditionValue(V::Bool(true))).unwrap(), true);
    assert_eq!(super::to_bool(&ConditionValue(V::Bool(false))).unwrap(), false);
    assert_eq!(super::to_bool(&ConditionValue(V::String("true".into()))).unwrap(), true);
    assert_eq!(super::to_bool(&ConditionValue(V::String("false".into()))).unwrap(), false);
    assert!(super::to_bool(&ConditionValue(V::Integer(10))).is_err());

    assert_eq!(super::to_int(&ConditionValue(V::Integer(10))).unwrap(), 10);
    assert_eq!(super::to_int(&ConditionValue(V::String("10".into()))).unwrap(), 10);

    assert_eq!(super::to_str(&ConditionValue(V::String("lastring".into()))).unwrap(), "lastring");
  }

  #[test]
  fn resolve_variable() {
    assert_eq!(super::resolve(&QString::new("aws".into(), "username".into())).unwrap(), Expr::var("input.aws.username"));
    assert_eq!(super::resolve(&QString::new("aws".into(), "tags/region".into())).unwrap(), Expr::var("input.aws.tags.region"));
    assert_eq!(super::resolve(&QString::unqualified("time".into())).unwrap(), Expr::var("input.time"));
  }

  #[test]
  fn string_not_equals() {
    let expr = build_condition("StringNotEquals", &[(QString::unqualified("env".into()), Value::One(ConditionValue(V::String("production".into()))))]).unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"input.env != "production""#);

    let expr = build_condition(
      "StringNotEquals",
      &[(
        QString::unqualified("env".into()),
        Value::Many(vec![ConditionValue(V::String("production".into())), ConditionValue(V::String("staging".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"every item in ["production", "staging"] { input.env != item }"#);
  }

  #[test]
  fn string_equals_ignore_case() {
    let expr = build_condition(
      "StringEqualsIgnoreCase",
      &[(QString::unqualified("username".into()), Value::One(ConditionValue(V::String("APOGNU".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"lower(input.username) == lower("APOGNU")"#);

    let expr = build_condition(
      "StringEqualsIgnoreCase",
      &[(
        QString::unqualified("username".into()),
        Value::Many(vec![ConditionValue(V::String("APOGNU".into())), ConditionValue(V::String("BOB".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"lower(["APOGNU", "BOB"][_]) == lower(input.username)"#);
  }

  #[test]
  fn string_not_equals_ignore_case() {
    let expr = build_condition(
      "StringNotEqualsIgnoreCase",
      &[(QString::unqualified("env".into()), Value::One(ConditionValue(V::String("PRODUCTION".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"lower(input.env) != lower("PRODUCTION")"#);
  }

  #[test]
  fn string_not_like() {
    let expr = build_condition("StringNotLike", &[(QString::unqualified("username".into()), Value::One(ConditionValue(V::String("admin-*".into()))))]).unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"not glob.match("admin-*", null, input.username)"#);

    let expr = build_condition(
      "StringNotLike",
      &[(
        QString::unqualified("username".into()),
        Value::Many(vec![ConditionValue(V::String("admin-*".into())), ConditionValue(V::String("root-*".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"every item in ["admin-*", "root-*"] { not glob.match(item, null, input.username) }"#);
  }

  #[test]
  fn numeric_equals() {
    let expr = build_condition("NumericEquals", &[(QString::unqualified("max_keys".into()), Value::One(ConditionValue(V::Integer(1000))))]).unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"input.max_keys == 1000"#);

    let expr = build_condition(
      "NumericEquals",
      &[(
        QString::unqualified("max_keys".into()),
        Value::Many(vec![ConditionValue(V::Integer(100)), ConditionValue(V::Integer(1000))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"[100, 1000][_] == input.max_keys"#);
  }

  #[test]
  fn numeric_less_than() {
    let expr = build_condition(
      "NumericLessThan",
      &[(QString::new("s3".into(), "content-length".into()), Value::One(ConditionValue(V::Integer(10485760))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"input.s3.content-length < 10485760"#);
  }

  #[test]
  fn numeric_greater_than() {
    let expr = build_condition("NumericGreaterThan", &[(QString::unqualified("age".into()), Value::One(ConditionValue(V::Integer(18))))]).unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"input.age > 18"#);
  }

  #[test]
  fn numeric_less_than_equals() {
    let expr = build_condition("NumericLessThanEquals", &[(QString::unqualified("max_size".into()), Value::One(ConditionValue(V::Integer(5000))))]).unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"input.max_size <= 5000"#);
  }

  #[test]
  fn numeric_greater_than_equals() {
    let expr = build_condition("NumericGreaterThanEquals", &[(QString::unqualified("min_size".into()), Value::One(ConditionValue(V::Integer(100))))]).unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"input.min_size >= 100"#);
  }

  #[test]
  fn date_equals() {
    let expr = build_condition(
      "DateEquals",
      &[(QString::new("aws".into(), "CurrentTime".into()), Value::One(ConditionValue(V::String("2025-01-01T00:00:00Z".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"time.parse_rfc3339_ns(input.aws.CurrentTime) == time.parse_rfc3339_ns("2025-01-01T00:00:00Z")"#
    );
  }

  #[test]
  fn date_greater_than() {
    let expr = build_condition(
      "DateGreaterThan",
      &[(QString::new("aws".into(), "CurrentTime".into()), Value::One(ConditionValue(V::String("2025-01-01T00:00:00Z".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"time.parse_rfc3339_ns(input.aws.CurrentTime) > time.parse_rfc3339_ns("2025-01-01T00:00:00Z")"#
    );
  }

  #[test]
  fn date_less_than() {
    let expr = build_condition(
      "DateLessThan",
      &[(QString::new("aws".into(), "CurrentTime".into()), Value::One(ConditionValue(V::String("2025-12-31T23:59:59Z".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"time.parse_rfc3339_ns(input.aws.CurrentTime) < time.parse_rfc3339_ns("2025-12-31T23:59:59Z")"#
    );
  }

  #[test]
  fn ip_address() {
    let expr = build_condition(
      "IpAddress",
      &[(QString::new("aws".into(), "SourceIp".into()), Value::One(ConditionValue(V::String("192.168.1.0/24".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"net.cidr_contains("192.168.1.0/24", input.aws.SourceIp)"#);

    let expr = build_condition(
      "IpAddress",
      &[(
        QString::new("aws".into(), "SourceIp".into()),
        Value::Many(vec![ConditionValue(V::String("192.168.1.0/24".into())), ConditionValue(V::String("10.0.0.0/8".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"net.cidr_contains(["192.168.1.0/24", "10.0.0.0/8"][_], input.aws.SourceIp)"#);
  }

  #[test]
  fn not_ip_address() {
    let expr = build_condition(
      "NotIpAddress",
      &[(QString::new("aws".into(), "SourceIp".into()), Value::One(ConditionValue(V::String("10.0.0.0/8".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"not net.cidr_contains("10.0.0.0/8", input.aws.SourceIp)"#);

    let expr = build_condition(
      "NotIpAddress",
      &[(
        QString::new("aws".into(), "SourceIp".into()),
        Value::Many(vec![ConditionValue(V::String("10.0.0.0/8".into())), ConditionValue(V::String("192.168.0.0/24".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in ["10.0.0.0/8", "192.168.0.0/24"] { not net.cidr_contains(item, input.aws.SourceIp) }"#
    );
  }
}
