use crate::{
  expression::{Expr, Str},
  extensions::TryMapExprIter,
  parser::Error,
};

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum SubstitutionError {
  #[error("nested interpolation: {0}")]
  NestedInterpolation(String),
  #[error("invalid characters: {0}")]
  InvalidCharacters(String),
  #[error("too many slashes: {0}")]
  TooManySlashes(String),
  #[error("empty expression")]
  EmptyExpression,
}

const INPUT_PREFIX: &str = "input.";

pub fn substitute_variables(template: &str) -> Result<Str, Error> {
  if !template.contains("${") {
    return Ok(Str::Plain(template.to_string()));
  }

  let mut result = String::with_capacity(template.len());
  let mut vars = vec![];
  let mut last_end = 0;
  let mut pos = 0;

  while pos < template.len() {
    if let Some(start_offset) = template[pos..].find("${") {
      let start = pos + start_offset;
      let search_start = start + 2;

      if let Some(relative_end) = template[search_start..].find('}') {
        let end = search_start + relative_end;
        let var_expr = &template[search_start..end];

        result.push_str(&template[last_end..start]);

        if let Some(special_value) = handle_special_variable(var_expr) {
          result.push_str(special_value);
          last_end = end + 1;
          pos = end + 1;
          continue;
        }

        let (var_part, default_value) = parse_variable_with_default(var_expr);

        validate_variable_expr(var_part)?;

        let mut variable = String::with_capacity(INPUT_PREFIX.len() + var_part.len());

        variable.push_str(INPUT_PREFIX);

        for c in var_part.chars() {
          variable.push(if c == ':' || c == '/' { '.' } else { c });
        }

        let variable: Expr = if let Some(default) = default_value {
          let (object, path) = {
            let mut parts = variable.split('.');
            let object = parts.next().unwrap().to_string();
            let path = parts.map_expr(Expr::str)?;

            (object, path)
          };

          Expr::call("object.get", vec![Expr::var(object), Expr::list(path), Expr::str(default)?])
        } else {
          Expr::var(variable)
        };

        result.push_str("%s");
        vars.push(variable);

        last_end = end + 1;
        pos = end + 1;
      } else {
        result.push_str(&template[last_end..]);
        break;
      }
    } else {
      result.push_str(&template[last_end..]);
      break;
    }
  }

  if !vars.is_empty() { Ok(Str::tmpl(result, vars)) } else { Ok(Str::Plain(result)) }
}

fn handle_special_variable(expr: &str) -> Option<&'static str> {
  match expr.trim() {
    "*" => Some("*"),
    "?" => Some("?"),
    "$" => Some("$"),
    _ => None,
  }
}

fn parse_variable_with_default(expr: &str) -> (&str, Option<&str>) {
  if let Some(comma_pos) = expr.find(',') {
    let var_part = expr[..comma_pos].trim();
    let default_part = expr[comma_pos + 1..].trim();

    if let Some(default_val) = extract_quoted_string(default_part) {
      return (var_part, Some(default_val));
    }
  }

  (expr, None)
}

fn extract_quoted_string(s: &str) -> Option<&str> {
  let trimmed = s.trim();

  if trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2 {
    return Some(&trimmed[1..trimmed.len() - 1]);
  }

  if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
    return Some(&trimmed[1..trimmed.len() - 1]);
  }

  None
}

fn validate_variable_expr(expr: &str) -> Result<(), SubstitutionError> {
  if expr.is_empty() {
    return Err(SubstitutionError::EmptyExpression);
  }

  if expr.contains("${") {
    return Err(SubstitutionError::NestedInterpolation(expr.to_string()));
  }

  if expr.contains('}') {
    return Err(SubstitutionError::InvalidCharacters(expr.to_string()));
  }

  let slash_count = expr.chars().filter(|&c| c == '/').count();
  if slash_count > 1 {
    return Err(SubstitutionError::TooManySlashes(expr.to_string()));
  }

  if !expr.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == ':' || c == '.' || c == '/') {
    return Err(SubstitutionError::InvalidCharacters(expr.to_string()));
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn simple() {
    let result = substitute_variables("Hello ${username}").unwrap();

    assert_eq!(result, Str::tmpl("Hello %s", vec![Expr::var("input.username")]));
  }

  #[test]
  fn multiple() {
    let result = substitute_variables("${first} ${last}").unwrap();

    assert_eq!(result, Str::tmpl("%s %s", vec![Expr::var("input.first"), Expr::var("input.last")]));
  }

  #[test]
  fn nested_object() {
    let result = substitute_variables("sudo${aws/username}").unwrap();

    assert_eq!(result, Str::tmpl("sudo%s", vec![Expr::var("input.aws.username")]));
  }

  #[test]
  fn noop() {
    let result = substitute_variables("No variables here").unwrap();

    assert_eq!(result, Str::Plain("No variables here".to_string()));
  }

  #[test]
  fn complex_template() {
    let result = substitute_variables("arn:aws:s3:::bucket-${env}/user/${aws/username}/data").unwrap();

    assert_eq!(result, Str::tmpl("arn:aws:s3:::bucket-%s/user/%s/data", vec![Expr::var("input.env"), Expr::var("input.aws.username")]));
  }

  #[test]
  fn qualified_variable() {
    let result = substitute_variables("sudo${aws:username}").unwrap();

    assert_eq!(result, Str::tmpl("sudo%s", vec![Expr::var("input.aws.username")]));
  }

  #[test]
  fn invalid_nested_interpolation() {
    let result = substitute_variables("Hello ${${username}}");

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidStringInterpolation(SubstitutionError::NestedInterpolation(_))));

    let result = substitute_variables("Test ${other${username}}");

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidStringInterpolation(SubstitutionError::NestedInterpolation(_))));

    let result = substitute_variables("Clean ${${var}text}");

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidStringInterpolation(SubstitutionError::NestedInterpolation(_))));
  }

  #[test]
  fn multiple_slashes() {
    let result = substitute_variables("${aws/user/name}");

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidStringInterpolation(SubstitutionError::TooManySlashes(_))));
  }

  #[test]
  fn invalid_characters() {
    let result = substitute_variables("${user@name}");

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidStringInterpolation(SubstitutionError::InvalidCharacters(_))));

    let result = substitute_variables("${user name}");

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidStringInterpolation(SubstitutionError::InvalidCharacters(_))));
  }

  #[test]
  fn empty_variable() {
    let result = substitute_variables("${}");

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidStringInterpolation(SubstitutionError::EmptyExpression)));
  }

  #[test]
  fn valid_characters() {
    let result = substitute_variables("${aws:user-name_v1.0}").unwrap();

    assert_eq!(result, Str::tmpl("%s", vec![Expr::var("input.aws.user-name_v1.0")]));
  }

  #[test]
  fn default_value_single_quotes() {
    let result = substitute_variables("${missing, 'default'}").unwrap();

    assert_eq!(
      result,
      Str::tmpl(
        "%s",
        vec![Expr::call(
          "object.get",
          vec![Expr::var("input"), Expr::list(vec![Expr::str("missing").unwrap()]), Expr::str("default").unwrap()]
        )]
      )
    );

    let result = substitute_variables("${missing , 'default value'}").unwrap();

    assert_eq!(
      result,
      Str::tmpl(
        "%s",
        vec![Expr::call(
          "object.get",
          vec![Expr::var("input"), Expr::list(vec![Expr::str("missing").unwrap()]), Expr::str("default value").unwrap()]
        )]
      )
    );
  }

  #[test]
  fn default_value_double_quotes() {
    let result = substitute_variables(r#"${missing, "default value"}"#).unwrap();

    assert_eq!(
      result,
      Str::tmpl(
        "%s",
        vec![Expr::call(
          "object.get",
          vec![Expr::var("input"), Expr::list(vec![Expr::str("missing").unwrap()]), Expr::str("default value").unwrap()]
        )]
      )
    );
  }

  #[test]
  fn default_value_nested_object() {
    let result = substitute_variables("${aws:tags/username, 'default'}").unwrap();

    assert_eq!(
      result,
      Str::tmpl(
        "%s",
        vec![Expr::call(
          "object.get",
          vec![
            Expr::var("input"),
            Expr::list(vec![Expr::str("aws").unwrap(), Expr::str("tags").unwrap(), Expr::str("username").unwrap()]),
            Expr::str("default").unwrap()
          ]
        )]
      )
    );
  }

  #[test]
  fn default_value_empty() {
    let result = substitute_variables("${missing, ''}").unwrap();

    assert_eq!(
      result,
      Str::tmpl(
        "%s",
        vec![Expr::call(
          "object.get",
          vec![Expr::var("input"), Expr::list(vec![Expr::str("missing").unwrap()]), Expr::str("").unwrap()]
        )]
      )
    );
  }

  #[test]
  fn default_value_no_quotes() {
    let result = substitute_variables("${missing, default}");

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidStringInterpolation(SubstitutionError::InvalidCharacters(_))));
  }

  #[test]
  fn default_value_mismatched_quotes() {
    let result = substitute_variables("${missing, 'default\"}");

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidStringInterpolation(SubstitutionError::InvalidCharacters(_))));

    let result = substitute_variables("${missing, \"default'}");

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidStringInterpolation(SubstitutionError::InvalidCharacters(_))));
  }

  #[test]
  fn exception_asterisk() {
    let result = substitute_variables("${*}").unwrap();

    assert_eq!(result, Str::Plain("*".to_string()));

    let result = substitute_variables("${ * }").unwrap();

    assert_eq!(result, Str::Plain("*".to_string()));
  }

  #[test]
  fn exception_question_mark() {
    let result = substitute_variables("${?}").unwrap();

    assert_eq!(result, Str::Plain("?".to_string()));

    let result = substitute_variables("${ ? }").unwrap();

    assert_eq!(result, Str::Plain("?".to_string()));
  }

  #[test]
  fn exception_dollar() {
    let result = substitute_variables("${$}").unwrap();

    assert_eq!(result, Str::Plain("$".to_string()));

    let result = substitute_variables("${ $ }").unwrap();

    assert_eq!(result, Str::Plain("$".to_string()));
  }

  #[test]
  fn complex_exception() {
    let result = substitute_variables("arn:aws:s3:::${bucket}/${*}").unwrap();

    assert_eq!(result, Str::Template("arn:aws:s3:::%s/*".into(), vec![Expr::var("input.bucket")]));

    let result = substitute_variables("Pattern: ${*}.txt and ${?}.log").unwrap();

    assert_eq!(result, Str::Plain("Pattern: *.txt and ?.log".to_string()));

    let result = substitute_variables("Price: ${$}10").unwrap();
    assert_eq!(result, Str::Plain("Price: $10".to_string()));

    let result = substitute_variables("${$}${$}${$}").unwrap();
    assert_eq!(result, Str::Plain("$$$".to_string()));
  }
}
