use crate::{expression::Expr, parser::Error};

pub trait TryMapExprIter {
  type Input;

  fn map_expr<F>(self, f: F) -> Result<Vec<Expr>, Error>
  where
    F: Fn(Self::Input) -> Result<Expr, Error>;
}

impl<I, T> TryMapExprIter for I
where
  I: IntoIterator<Item = T>,
{
  type Input = T;

  fn map_expr<F>(self, f: F) -> Result<Vec<Expr>, Error>
  where
    F: Fn(Self::Input) -> Result<Expr, Error>,
  {
    let mut out = vec![];

    for item in self.into_iter() {
      out.push(f(item)?);
    }

    Ok(out)
  }
}
