use std::{
    env,
    error::Error,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use strum::{EnumIter, IntoEnumIterator};

#[derive(Serialize, Deserialize, EnumIter)]
pub enum Mode {
    Standard,
    Safe,
    Clean,
}

impl Mode {
    pub fn ip_address(&self) -> String {
        match self {
            Mode::Standard => String::from("1.1.1.1"),
            Mode::Safe => String::from("1.1.1.2"),
            Mode::Clean => String::from("1.1.1.3"),
        }
    }
}

impl From<&str> for Mode {
    fn from(input: &str) -> Mode {
        for resolver in Mode::iter() {
            let resolver_value = resolver.ip_address();

            if input == resolver_value {
                return resolver;
            }
        }

        panic!("Invalid mode `{}`", input);
    }
}

#[derive(Serialize, Deserialize)]
pub struct SwiftConfig {
    pub mode: Mode,
}

impl std::default::Default for SwiftConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Standard,
        }
    }
}

pub fn get_config() -> Result<SwiftConfig, Box<dyn Error>> {
    let config_path = get_path().join("config");
    let config: SwiftConfig = confy::load(&config_path.to_string_lossy(), None)?;

    Ok(config)
}

pub fn get_path() -> PathBuf {
    if cfg!(debug_assertions) {
        env::current_dir().unwrap()
    } else {
        Path::new("/etc/swiftdns/").to_path_buf()
    }
}
