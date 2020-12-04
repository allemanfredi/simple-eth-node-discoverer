#[derive(Debug, Clone)]
pub struct AppError {
    pub msg: String,
}

impl AppError {
    pub fn new(msg: &str) -> AppError {
        AppError {
            msg: String::from(msg),
        }
    }
}
