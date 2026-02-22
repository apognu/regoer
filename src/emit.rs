use crate::{
  Error,
  expression::{Expr, Repr},
};

macro_rules! emit {
    ($buf:expr, $($item:expr),* $(,)?) => {
        $( $item.emit($buf)?; )*
    };
}

pub trait Emit {
  fn emit(&self, w: &mut String) -> Result<(), Error>;
}

impl Emit for Expr {
  fn emit(&self, w: &mut String) -> Result<(), Error> {
    self.repr(w)
  }
}

impl Emit for &[Expr] {
  fn emit(&self, w: &mut String) -> Result<(), Error> {
    self.repr(w)
  }
}

impl Emit for &str {
  fn emit(&self, w: &mut String) -> Result<(), Error> {
    w.push_str(self);

    Ok(())
  }
}

impl Emit for char {
  fn emit(&self, w: &mut String) -> Result<(), Error> {
    w.push(*self);

    Ok(())
  }
}
