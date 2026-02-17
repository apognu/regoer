use aws_iam::model::{ConditionOperator, ConditionOperatorQuantifier, GlobalConditionOperator, QString};

use crate::{
  expression::Expr,
  functions::Func,
  parser::Error,
  values::{ConditionValue, Value},
};

pub type Conditions = Vec<(ConditionOperator, Vec<CondPair>)>;
pub type CondPair = (QString, Value<ConditionValue>);
pub type OperatorFunc<'f> = &'f dyn Fn(Box<Expr>, Box<Expr>) -> Expr;
pub type IdOperatorFunc<'f> = &'f dyn Fn(Expr) -> Expr;

trait Negatable {
  fn is_neg(&self) -> bool;
  fn apply(&self, ctxvalue: Expr, polvalues: Vec<Expr>, negative: bool, expr: impl Fn(Expr, Expr) -> Expr) -> Result<Expr, Error>;
}

impl Negatable for ConditionOperator {
  fn is_neg(&self) -> bool {
    use GlobalConditionOperator::*;

    matches!(
      self.operator,
      StringNotEquals | StringNotEqualsIgnoreCase | NumericNotEquals | StringNotLike | NotIpAddress | DateNotEquals
    )
  }

  fn apply(&self, ctxvalue: Expr, polvalues: Vec<Expr>, negative: bool, expr: impl Fn(Expr, Expr) -> Expr) -> Result<Expr, Error> {
    use ConditionOperatorQuantifier::*;

    match (self.quantifier.as_ref().unwrap(), negative) {
      (_, true) => {
        let outer_var = Expr::item();
        let inner_var = Expr::var("val");

        let inner = Expr::Every(inner_var.clone().boxed(), Expr::list(polvalues).boxed(), expr(inner_var, outer_var.clone()).boxed());

        Ok(Expr::Every(outer_var.boxed(), Func::to_array(ctxvalue).boxed(), inner.boxed()))
      }

      (ForAnyValue, false) => Ok(expr(Expr::AnyIn(Expr::list(polvalues).boxed()), Expr::AnyIn(Func::to_array(ctxvalue).boxed()))),

      (ForAllValues, false) => {
        let condition = expr(Expr::AnyIn(Expr::list(polvalues).boxed()), Expr::item());

        Ok(Expr::Every(Expr::item().boxed(), Func::to_array(ctxvalue).boxed(), condition.boxed()))
      }
    }
  }
}

pub fn build_condition(operator: &ConditionOperator, condition: &[CondPair]) -> Result<Vec<Expr>, Error> {
  use aws_iam::model::GlobalConditionOperator::*;

  match &operator.operator {
    Bool => condition.iter().try_fold(vec![], |mut acc, (attr, values)| {
      acc.push(match values.map(to_bool)? {
        Value::One(one) => Expr::Eq(resolve(attr)?.boxed(), one.boxed()),
        Value::Many(list) => Expr::Eq(Expr::AnyIn(Expr::list(list).boxed()).boxed(), resolve(attr)?.boxed()),
      });

      Ok::<_, Error>(acc)
    }),

    StringEquals => compare(operator, condition, to_str, |polvalue, ctxvalue| Expr::Eq(polvalue.boxed(), ctxvalue.boxed())),
    StringNotEquals => compare(operator, condition, to_str, |polvalue, ctxvalue| Expr::Ne(polvalue.boxed(), ctxvalue.boxed())),
    StringEqualsIgnoreCase => compare(operator, condition, to_str, |polvalue, ctxvalue| Expr::Eq(Func::lower(polvalue).boxed(), Func::lower(ctxvalue).boxed())),
    StringNotEqualsIgnoreCase => compare(operator, condition, to_str, |polvalue, ctxvalue| Expr::Ne(Func::lower(polvalue).boxed(), Func::lower(ctxvalue).boxed())),
    StringLike => compare(operator, condition, to_str, Func::glob),
    StringNotLike => compare(operator, condition, to_str, |polvalue, ctxvalue| Expr::neg(Func::glob(polvalue, ctxvalue))),

    NumericEquals => compare(operator, condition, to_int, |polvalue, ctxvalue| Expr::Eq(polvalue.boxed(), ctxvalue.boxed())),
    NumericNotEquals => compare(operator, condition, to_int, |polvalue, ctxvalue| Expr::Ne(polvalue.boxed(), ctxvalue.boxed())),
    NumericLessThan => compare(operator, condition, to_int, |polvalue, ctxvalue| Expr::Lt(ctxvalue.boxed(), polvalue.boxed())),
    NumericLessThanEquals => compare(operator, condition, to_int, |polvalue, ctxvalue| Expr::Lte(ctxvalue.boxed(), polvalue.boxed())),
    NumericGreaterThan => compare(operator, condition, to_int, |polvalue, ctxvalue| Expr::Gt(ctxvalue.boxed(), polvalue.boxed())),
    NumericGreaterThanEquals => compare(operator, condition, to_int, |polvalue, ctxvalue| Expr::Gte(ctxvalue.boxed(), polvalue.boxed())),

    DateEquals => compare(operator, condition, to_str, |polvalue, ctxvalue| {
      Expr::Eq(Func::datetime(polvalue).boxed(), Func::datetime(ctxvalue).boxed())
    }),
    DateNotEquals => compare(operator, condition, to_str, |polvalue, ctxvalue| {
      Expr::Ne(Func::datetime(polvalue).boxed(), Func::datetime(ctxvalue).boxed())
    }),
    DateGreaterThan => compare(operator, condition, to_str, |polvalue, ctxvalue| {
      Expr::Gt(Func::datetime(ctxvalue).boxed(), Func::datetime(polvalue).boxed())
    }),
    DateGreaterThanEquals => compare(operator, condition, to_str, |polvalue, ctxvalue| {
      Expr::Gte(Func::datetime(ctxvalue).boxed(), Func::datetime(polvalue).boxed())
    }),
    DateLessThan => compare(operator, condition, to_str, |polvalue, ctxvalue| {
      Expr::Lt(Func::datetime(ctxvalue).boxed(), Func::datetime(polvalue).boxed())
    }),
    DateLessThanEquals => compare(operator, condition, to_str, |polvalue, ctxvalue| {
      Expr::Lte(Func::datetime(ctxvalue).boxed(), Func::datetime(polvalue).boxed())
    }),

    IpAddress => compare(operator, condition, to_str, Func::cidr_contains),
    NotIpAddress => compare(operator, condition, to_str, |polvalue, ctxvalue| Expr::neg(Func::cidr_contains(polvalue, ctxvalue))),

    _ => Err(Error::UnsupportedFunction(format!("{:?}", operator.operator)))?,
  }
}

fn compare<F, B>(operator: &ConditionOperator, condition: &[(QString, Value<ConditionValue>)], converter: F, build_expr: B) -> Result<Vec<Expr>, Error>
where
  F: Fn(&ConditionValue) -> Result<Expr, Error>,
  B: Fn(Expr, Expr) -> Expr,
{
  let is_neg = operator.is_neg();

  condition.iter().try_fold(vec![], |mut acc, (attr, values)| {
    let ctxvalue = resolve(attr)?;

    acc.push(match values.map(&converter)? {
      Value::One(polvalue) => match operator.quantifier {
        Some(_) => operator.apply(ctxvalue, vec![polvalue], is_neg, &build_expr)?,
        None => build_expr(polvalue, ctxvalue),
      },

      Value::Many(polvalues) => match operator.quantifier {
        Some(_) => operator.apply(ctxvalue, polvalues, is_neg, &build_expr)?,
        None => match is_neg {
          false => build_expr(Expr::AnyIn(Expr::list(polvalues).boxed()), ctxvalue),
          true => Expr::every(polvalues, |polvalue| Ok(build_expr(polvalue, ctxvalue.clone())))?,
        },
      },
    });

    Ok::<_, Error>(acc)
  })
}

fn to_bool(s: &ConditionValue) -> Result<Expr, Error> {
  use aws_iam::model::ConditionValue::*;

  match &**s {
    Bool(b) => Expr::bool(*b),
    String(s) if s == "true" => Expr::bool(true),
    String(s) if s == "false" => Expr::bool(false),
    _ => Err(Error::InvalidType("bool", format!("{s:?}")))?,
  }
}

fn to_str(s: &ConditionValue) -> Result<Expr, Error> {
  use aws_iam::model::ConditionValue::*;

  match &**s {
    String(s) => Expr::str(s),
    _ => Err(Error::InvalidType("string", format!("{s:?}")))?,
  }
}

fn to_int(s: &ConditionValue) -> Result<Expr, Error> {
  use aws_iam::model::ConditionValue::*;

  match &**s {
    Integer(i) => Expr::int(*i),
    String(s) => Expr::int(s.parse().map_err(|_| Error::InvalidType("integer", s.to_string()))?),
    _ => Err(Error::InvalidType("integer", format!("{s:?}")))?,
  }
}

fn resolve(var: &QString) -> Result<Expr, Error> {
  Ok(match var.qualifier() {
    Some(q) => Expr::var(format!("input.{}.{}", q, var.value().replace('/', "."))),
    _ => Expr::var(format!("input.{}", var.to_string().replace('/', "."))),
  })
}

#[cfg(test)]
mod tests {
  use aws_iam::model::{ConditionOperator, ConditionValue as V, GlobalConditionOperator::*, QString};

  use crate::{
    conditions::build_condition,
    expression::{Expr, Repr, Str},
    values::{ConditionValue, Value},
  };

  #[test]
  fn bool_equals() {
    let expr = build_condition(&ConditionOperator::new(Bool), &[(QString::unqualified("username".into()), Value::One(ConditionValue(V::Bool(true))))]).unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"input.username == true"#);

    let expr = build_condition(
      &ConditionOperator::new(Bool),
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
    let expr = build_condition(
      &ConditionOperator::new(StringEquals),
      &[(QString::unqualified("username".into()), Value::One(ConditionValue(V::String("apognu".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#""apognu" == input.username"#);

    let expr = build_condition(
      &ConditionOperator::new(StringEquals),
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
    let expr = build_condition(
      &ConditionOperator::new(StringLike),
      &[(QString::unqualified("username".into()), Value::One(ConditionValue(V::String("apognu".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"glob.match("apognu", null, input.username)"#);

    let expr = build_condition(
      &ConditionOperator::new(StringLike),
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
    assert_eq!(super::to_bool(&ConditionValue(V::Bool(true))).unwrap(), Expr::Bool(true));
    assert_eq!(super::to_bool(&ConditionValue(V::Bool(false))).unwrap(), Expr::Bool(false));
    assert_eq!(super::to_bool(&ConditionValue(V::String("true".into()))).unwrap(), Expr::Bool(true));
    assert_eq!(super::to_bool(&ConditionValue(V::String("false".into()))).unwrap(), Expr::Bool(false));
    assert!(super::to_bool(&ConditionValue(V::Integer(10))).is_err());

    assert_eq!(super::to_int(&ConditionValue(V::Integer(10))).unwrap(), Expr::Int(10));
    assert_eq!(super::to_int(&ConditionValue(V::String("10".into()))).unwrap(), Expr::Int(10));

    assert_eq!(super::to_str(&ConditionValue(V::String("lastring".into()))).unwrap(), Expr::Str(Str::Plain("lastring".into())));
  }

  #[test]
  fn resolve_variable() {
    assert_eq!(super::resolve(&QString::new("aws".into(), "username".into())).unwrap(), Expr::var("input.aws.username"));
    assert_eq!(super::resolve(&QString::new("aws".into(), "tags/region".into())).unwrap(), Expr::var("input.aws.tags.region"));
    assert_eq!(super::resolve(&QString::unqualified("time".into())).unwrap(), Expr::var("input.time"));
  }

  #[test]
  fn string_not_equals() {
    let expr = build_condition(
      &ConditionOperator::new(StringNotEquals),
      &[(QString::unqualified("env".into()), Value::One(ConditionValue(V::String("production".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#""production" != input.env"#);

    let expr = build_condition(
      &ConditionOperator::new(StringNotEquals),
      &[(
        QString::unqualified("env".into()),
        Value::Many(vec![ConditionValue(V::String("production".into())), ConditionValue(V::String("staging".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"every item in ["production", "staging"] { item != input.env }"#);
  }

  #[test]
  fn string_equals_ignore_case() {
    let expr = build_condition(
      &ConditionOperator::new(StringEqualsIgnoreCase),
      &[(QString::unqualified("username".into()), Value::One(ConditionValue(V::String("APOGNU".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"lower("APOGNU") == lower(input.username)"#);

    let expr = build_condition(
      &ConditionOperator::new(StringEqualsIgnoreCase),
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
      &ConditionOperator::new(StringNotEqualsIgnoreCase),
      &[(QString::unqualified("env".into()), Value::One(ConditionValue(V::String("PRODUCTION".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"lower("PRODUCTION") != lower(input.env)"#);
  }

  #[test]
  fn string_not_like() {
    let expr = build_condition(
      &ConditionOperator::new(StringNotLike),
      &[(QString::unqualified("username".into()), Value::One(ConditionValue(V::String("admin-*".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"not glob.match("admin-*", null, input.username)"#);

    let expr = build_condition(
      &ConditionOperator::new(StringNotLike),
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
    let expr = build_condition(
      &ConditionOperator::new(NumericEquals),
      &[(QString::unqualified("max_keys".into()), Value::One(ConditionValue(V::Integer(1000))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"1000 == input.max_keys"#);

    let expr = build_condition(
      &ConditionOperator::new(NumericEquals),
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
      &ConditionOperator::new(NumericLessThan),
      &[(QString::new("s3".into(), "content-length".into()), Value::One(ConditionValue(V::Integer(10485760))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"input.s3.content-length < 10485760"#);
  }

  #[test]
  fn numeric_greater_than() {
    let expr = build_condition(
      &ConditionOperator::new(NumericGreaterThan),
      &[(QString::unqualified("age".into()), Value::One(ConditionValue(V::Integer(18))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"input.age > 18"#);
  }

  #[test]
  fn numeric_less_than_equals() {
    let expr = build_condition(
      &ConditionOperator::new(NumericLessThanEquals),
      &[(QString::unqualified("max_size".into()), Value::One(ConditionValue(V::Integer(5000))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"input.max_size <= 5000"#);
  }

  #[test]
  fn numeric_greater_than_equals() {
    let expr = build_condition(
      &ConditionOperator::new(NumericGreaterThanEquals),
      &[(QString::unqualified("min_size".into()), Value::One(ConditionValue(V::Integer(100))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"input.min_size >= 100"#);
  }

  #[test]
  fn date_equals() {
    let expr = build_condition(
      &ConditionOperator::new(DateEquals),
      &[(QString::new("aws".into(), "CurrentTime".into()), Value::One(ConditionValue(V::String("2025-01-01T00:00:00Z".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"time.parse_rfc3339_ns("2025-01-01T00:00:00Z") == time.parse_rfc3339_ns(input.aws.CurrentTime)"#
    );
  }

  #[test]
  fn date_greater_than() {
    let expr = build_condition(
      &ConditionOperator::new(DateGreaterThan),
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
      &ConditionOperator::new(DateLessThan),
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
      &ConditionOperator::new(IpAddress),
      &[(QString::new("aws".into(), "SourceIp".into()), Value::One(ConditionValue(V::String("192.168.1.0/24".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"net.cidr_contains("192.168.1.0/24", input.aws.SourceIp)"#);

    let expr = build_condition(
      &ConditionOperator::new(IpAddress),
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
      &ConditionOperator::new(NotIpAddress),
      &[(QString::new("aws".into(), "SourceIp".into()), Value::One(ConditionValue(V::String("10.0.0.0/8".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"not net.cidr_contains("10.0.0.0/8", input.aws.SourceIp)"#);

    let expr = build_condition(
      &ConditionOperator::new(NotIpAddress),
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

  #[test]
  fn for_any_value_string_equals() {
    // ForAnyValue: at least one value in the request matches at least one value in the policy
    let expr = build_condition(
      &ConditionOperator::new(StringEquals).for_any(),
      &[(
        QString::unqualified("tags".into()),
        Value::Many(vec![ConditionValue(V::String("production".into())), ConditionValue(V::String("staging".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"["production", "staging"][_] == to_array(object.get(input, "tags", []))[_]"#);
  }

  #[test]
  fn for_any_value_string_not_equals() {
    // ForAnyValue with negation: none of the values in the request match any value in the policy
    let expr = build_condition(
      &ConditionOperator::new(StringNotEquals).for_any(),
      &[(
        QString::unqualified("tags".into()),
        Value::Many(vec![ConditionValue(V::String("production".into())), ConditionValue(V::String("staging".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in to_array(object.get(input, "tags", [])) { every val in ["production", "staging"] { val != item } }"#
    );
  }

  #[test]
  fn for_all_values_string_equals() {
    // ForAllValues: all values in the request must match at least one value in the policy
    let expr = build_condition(
      &ConditionOperator::new(StringEquals).for_all(),
      &[(
        QString::unqualified("tags".into()),
        Value::Many(vec![ConditionValue(V::String("production".into())), ConditionValue(V::String("staging".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    // This should check that every item in input.tags matches at least one of the policy values
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in to_array(object.get(input, "tags", [])) { ["production", "staging"][_] == item }"#
    );
  }

  #[test]
  fn for_all_values_string_not_equals() {
    // ForAllValues with negation: all values in the request must not match any value in the policy
    let expr = build_condition(
      &ConditionOperator::new(StringNotEquals).for_all(),
      &[(
        QString::unqualified("tags".into()),
        Value::Many(vec![ConditionValue(V::String("production".into())), ConditionValue(V::String("staging".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in to_array(object.get(input, "tags", [])) { every val in ["production", "staging"] { val != item } }"#
    );
  }

  #[test]
  fn for_any_value_numeric() {
    let expr = build_condition(
      &ConditionOperator::new(NumericEquals).for_any(),
      &[(QString::unqualified("ports".into()), Value::Many(vec![ConditionValue(V::Integer(80)), ConditionValue(V::Integer(443))]))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"[80, 443][_] == to_array(object.get(input, "ports", []))[_]"#);
  }

  #[test]
  fn for_all_values_numeric() {
    let expr = build_condition(
      &ConditionOperator::new(NumericGreaterThan).for_all(),
      &[(
        QString::unqualified("ports".into()),
        Value::Many(vec![ConditionValue(V::Integer(1024)), ConditionValue(V::Integer(2048))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"every item in to_array(object.get(input, "ports", [])) { item > [1024, 2048][_] }"#);
  }

  #[test]
  fn for_any_value_string_like() {
    let expr = build_condition(
      &ConditionOperator::new(StringLike).for_any(),
      &[(
        QString::unqualified("paths".into()),
        Value::Many(vec![ConditionValue(V::String("/home/*".into())), ConditionValue(V::String("/tmp/*".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"glob.match(["/home/*", "/tmp/*"][_], null, to_array(object.get(input, "paths", []))[_])"#);
  }

  #[test]
  fn for_all_values_string_like() {
    let expr = build_condition(
      &ConditionOperator::new(StringLike).for_all(),
      &[(
        QString::unqualified("paths".into()),
        Value::Many(vec![ConditionValue(V::String("/safe/*".into())), ConditionValue(V::String("/public/*".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in to_array(object.get(input, "paths", [])) { glob.match(["/safe/*", "/public/*"][_], null, item) }"#
    );
  }

  #[test]
  fn for_any_value_ip_address() {
    let expr = build_condition(
      &ConditionOperator::new(IpAddress).for_any(),
      &[(
        QString::new("aws".into(), "SourceIp".into()),
        Value::Many(vec![ConditionValue(V::String("10.0.0.0/8".into())), ConditionValue(V::String("192.168.0.0/16".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"net.cidr_contains(["10.0.0.0/8", "192.168.0.0/16"][_], to_array(object.get(input.aws, "SourceIp", []))[_])"#
    );
  }

  #[test]
  fn for_all_values_ip_address() {
    let expr = build_condition(
      &ConditionOperator::new(IpAddress).for_all(),
      &[(
        QString::new("aws".into(), "SourceIp".into()),
        Value::Many(vec![ConditionValue(V::String("10.0.0.0/8".into())), ConditionValue(V::String("192.168.0.0/16".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in to_array(object.get(input.aws, "SourceIp", [])) { net.cidr_contains(["10.0.0.0/8", "192.168.0.0/16"][_], item) }"#
    );
  }

  #[test]
  fn for_any_value_numeric_less_than() {
    let expr = build_condition(
      &ConditionOperator::new(NumericLessThan).for_any(),
      &[(
        QString::unqualified("values".into()),
        Value::Many(vec![ConditionValue(V::Integer(100)), ConditionValue(V::Integer(200))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"to_array(object.get(input, "values", []))[_] < [100, 200][_]"#);
  }

  #[test]
  fn for_all_values_numeric_less_than_equals() {
    let expr = build_condition(
      &ConditionOperator::new(NumericLessThanEquals).for_all(),
      &[(
        QString::unqualified("limits".into()),
        Value::Many(vec![ConditionValue(V::Integer(1000)), ConditionValue(V::Integer(5000))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"every item in to_array(object.get(input, "limits", [])) { item <= [1000, 5000][_] }"#);
  }

  #[test]
  fn for_any_value_date_greater_than() {
    let expr = build_condition(
      &ConditionOperator::new(DateGreaterThan).for_any(),
      &[(
        QString::new("aws".into(), "TokenIssueTime".into()),
        Value::Many(vec![ConditionValue(V::String("2025-01-01T00:00:00Z".into())), ConditionValue(V::String("2025-06-01T00:00:00Z".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"time.parse_rfc3339_ns(to_array(object.get(input.aws, "TokenIssueTime", []))[_]) > time.parse_rfc3339_ns(["2025-01-01T00:00:00Z", "2025-06-01T00:00:00Z"][_])"#
    );
  }

  #[test]
  fn for_all_values_date_less_than() {
    let expr = build_condition(
      &ConditionOperator::new(DateLessThan).for_all(),
      &[(
        QString::new("aws".into(), "TokenExpiry".into()),
        Value::Many(vec![ConditionValue(V::String("2026-12-31T23:59:59Z".into())), ConditionValue(V::String("2027-12-31T23:59:59Z".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in to_array(object.get(input.aws, "TokenExpiry", [])) { time.parse_rfc3339_ns(item) < time.parse_rfc3339_ns(["2026-12-31T23:59:59Z", "2027-12-31T23:59:59Z"][_]) }"#
    );
  }

  #[test]
  fn for_any_value_string_not_like() {
    let expr = build_condition(
      &ConditionOperator::new(StringNotLike).for_any(),
      &[(
        QString::unqualified("paths".into()),
        Value::Many(vec![ConditionValue(V::String("/admin/*".into())), ConditionValue(V::String("/root/*".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in to_array(object.get(input, "paths", [])) { every val in ["/admin/*", "/root/*"] { not glob.match(val, null, item) } }"#
    );
  }

  #[test]
  fn for_all_values_numeric_not_equals() {
    let expr = build_condition(
      &ConditionOperator::new(NumericNotEquals).for_all(),
      &[(QString::unqualified("ports".into()), Value::Many(vec![ConditionValue(V::Integer(22)), ConditionValue(V::Integer(23))]))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in to_array(object.get(input, "ports", [])) { every val in [22, 23] { val != item } }"#
    );
  }

  // Single policy value with qualifiers — the value must be wrapped into a list so qualifier
  // semantics apply correctly against the multi-valued context attribute.

  #[test]
  fn for_any_value_string_equals_single_policy_value() {
    let expr = build_condition(
      &ConditionOperator::new(StringEquals).for_any(),
      &[(QString::unqualified("tags".into()), Value::One(ConditionValue(V::String("production".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    // At least one context value must equal the single policy value
    assert_eq!(expr[0].repr().unwrap(), r#"["production"][_] == to_array(object.get(input, "tags", []))[_]"#);
  }

  #[test]
  fn for_all_values_string_equals_single_policy_value() {
    let expr = build_condition(
      &ConditionOperator::new(StringEquals).for_all(),
      &[(QString::unqualified("tags".into()), Value::One(ConditionValue(V::String("production".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    // Every context value must equal the single policy value
    assert_eq!(expr[0].repr().unwrap(), r#"every item in to_array(object.get(input, "tags", [])) { ["production"][_] == item }"#);
  }

  #[test]
  fn for_any_value_string_not_equals_single_policy_value() {
    let expr = build_condition(
      &ConditionOperator::new(StringNotEquals).for_any(),
      &[(QString::unqualified("tags".into()), Value::One(ConditionValue(V::String("production".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    // No context value must equal the single policy value
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in to_array(object.get(input, "tags", [])) { every val in ["production"] { val != item } }"#
    );
  }

  #[test]
  fn for_all_values_string_not_equals_single_policy_value() {
    let expr = build_condition(
      &ConditionOperator::new(StringNotEquals).for_all(),
      &[(QString::unqualified("tags".into()), Value::One(ConditionValue(V::String("production".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in to_array(object.get(input, "tags", [])) { every val in ["production"] { val != item } }"#
    );
  }

  #[test]
  fn for_any_value_numeric_equals_single_policy_value() {
    let expr = build_condition(
      &ConditionOperator::new(NumericEquals).for_any(),
      &[(QString::unqualified("ports".into()), Value::One(ConditionValue(V::Integer(443))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"[443][_] == to_array(object.get(input, "ports", []))[_]"#);
  }

  #[test]
  fn for_all_values_numeric_equals_single_policy_value() {
    let expr = build_condition(
      &ConditionOperator::new(NumericEquals).for_all(),
      &[(QString::unqualified("ports".into()), Value::One(ConditionValue(V::Integer(443))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"every item in to_array(object.get(input, "ports", [])) { [443][_] == item }"#);
  }

  #[test]
  fn for_any_value_string_like_single_policy_value() {
    let expr = build_condition(
      &ConditionOperator::new(StringLike).for_any(),
      &[(QString::unqualified("paths".into()), Value::One(ConditionValue(V::String("/home/*".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(expr[0].repr().unwrap(), r#"glob.match(["/home/*"][_], null, to_array(object.get(input, "paths", []))[_])"#);
  }

  #[test]
  fn for_all_values_string_like_single_policy_value() {
    let expr = build_condition(
      &ConditionOperator::new(StringLike).for_all(),
      &[(QString::unqualified("paths".into()), Value::One(ConditionValue(V::String("/safe/*".into()))))],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in to_array(object.get(input, "paths", [])) { glob.match(["/safe/*"][_], null, item) }"#
    );
  }

  #[test]
  fn for_all_values_string_not_like() {
    let expr = build_condition(
      &ConditionOperator::new(StringNotLike).for_all(),
      &[(
        QString::unqualified("paths".into()),
        Value::Many(vec![ConditionValue(V::String("/admin/*".into())), ConditionValue(V::String("/root/*".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in to_array(object.get(input, "paths", [])) { every val in ["/admin/*", "/root/*"] { not glob.match(val, null, item) } }"#
    );
  }

  #[test]
  fn for_any_value_not_ip_address() {
    let expr = build_condition(
      &ConditionOperator::new(NotIpAddress).for_any(),
      &[(
        QString::new("aws".into(), "SourceIp".into()),
        Value::Many(vec![ConditionValue(V::String("10.0.0.0/8".into())), ConditionValue(V::String("192.168.0.0/16".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in to_array(object.get(input.aws, "SourceIp", [])) { every val in ["10.0.0.0/8", "192.168.0.0/16"] { not net.cidr_contains(val, item) } }"#
    );
  }

  #[test]
  fn for_all_values_not_ip_address() {
    let expr = build_condition(
      &ConditionOperator::new(NotIpAddress).for_all(),
      &[(
        QString::new("aws".into(), "SourceIp".into()),
        Value::Many(vec![ConditionValue(V::String("10.0.0.0/8".into())), ConditionValue(V::String("192.168.0.0/16".into()))]),
      )],
    )
    .unwrap();

    assert_eq!(expr.len(), 1);
    assert_eq!(
      expr[0].repr().unwrap(),
      r#"every item in to_array(object.get(input.aws, "SourceIp", [])) { every val in ["10.0.0.0/8", "192.168.0.0/16"] { not net.cidr_contains(val, item) } }"#
    );
  }
}
