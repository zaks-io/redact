pub trait Must<T> {
    fn must(self) -> T;
}
impl<T, E> Must<T> for Result<T, E> {
    fn must(self) -> T {
        self.unwrap_or_else(|_| panic!("synthetic test operation failed"))
    }
}
impl<T> Must<T> for Option<T> {
    fn must(self) -> T {
        self.unwrap_or_else(|| panic!("synthetic test setup missing value"))
    }
}
pub trait MustErr<E> {
    fn must_err(self) -> E;
}
impl<T, E> MustErr<E> for Result<T, E> {
    fn must_err(self) -> E {
        match self {
            Err(error) => error,
            Ok(_) => panic!("expected synthetic test failure"),
        }
    }
}
