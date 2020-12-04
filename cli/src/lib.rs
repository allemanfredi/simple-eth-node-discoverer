use std::env;

use utils::app_error::AppError;

pub struct Args {
    pub tcp_port: u16,
}

pub struct Cli {}

impl Cli {
    pub fn parse_params() -> Result<Args, AppError> {
        println!("Parsing command line arguments...");

        let args: Vec<String> = env::args().collect();

        match args.len() {
            2 => {
                let tcp_port: u16 = match args[1].parse() {
                    Ok(n) => n,
                    Err(_) => {
                        return Err(AppError::new("Port argument not an integer"));
                    }
                };

                Ok(Args { tcp_port: tcp_port })
            }
            _ => Ok(Args { tcp_port: 5888 }),
        }
    }
}
