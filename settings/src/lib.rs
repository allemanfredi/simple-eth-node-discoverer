use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;

use utils::app_error::AppError;

#[derive(Debug, Deserialize)]
pub struct DefaultPeer {
    pub ip: String,
    pub tcp_port: u16,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub default_peers: Vec<DefaultPeer>,
}

impl Settings {
    pub fn load() -> Result<Settings, AppError> {
        let file = match File::open("./settings.json") {
            Ok(file) => file,
            Err(_err) => return Err(AppError::new("Error while opening settings.json")),
        };
        let settings: Settings = match serde_json::from_reader(BufReader::new(file)) {
            Ok(res) => res,
            Err(_err) => return Err(AppError::new("Error while parsing settings.json")),
        };
        Ok(settings)
    }
}
