pub mod arg_handling {
    use crate::{ERROR, SUCCESS};
    use std::process::exit;

    /*
       Enum we will use to pass encryption info for creation of context
    */
    enum EncryptionInfo {
        AesCbc,
        AesCtr,
        AesEcb,
        Rc4,
    }

    enum KeySize {
        Size128,
        Size192,
        Size256,
    }

    pub struct KryptosConfig {
        pub enc_type: EncryptionInfo,
        pub key_size: KeySize,
        pub optional_key: Option<String>,
        pub port: u16,
    }

    pub fn parse_arguments(args: Vec<String>) -> KryptosConfig {
        let use_key: bool = args.len() == 5;
        if (args.len() > 4) {
            println!("Too many arguments!");
            println!("Usage: kryptos port encryption-type key-size (optional provided key, generated otherwise)");
            println!("Try --help for help.");
            exit(ERROR);
        }

        if { args.len() < 4 } {
            println!("Usage: kryptos port encryption-type key-size (optional provided key, generated otherwise)");
            println!("Try --help for help.");
            exit(ERROR);
        }
        if (args[1] == "--help") {
            println!("Usage: kryptos port encryption-type key-size (optional provided key, generated otherwise)");
            println!("Encryption Options: AesCbc, AesCtr, AesEcb (unsafe), Rc4 (unsafe)");
            println!("Key Size Options: 128, 192, 256");
            println!("This is a simple encrypted telnet chat server written in Rust.");
            println!("The client is available on my github");
            println!("Options: --help, --version");
            exit(SUCCESS);
        }

        if (args[1] == "--version") {
            println!("Kryptos server version {}", env!("CARGO_PKG_VERSION"));
            exit(SUCCESS);
        }

        if { args.len() < 4 } {
            println!("Usage: kryptos port encryption-type key-size (optional provided key, generated otherwise)");
            println!("Try --help for help.");
            exit(ERROR);
        }

        let port = match args[1].parse::<u16>() {
            Ok(x) if x < 1024 => {
                eprintln!("Port must not be in the reserved range!");
                exit(ERROR);
            }
            Ok(x) => x,
            Err(_) => {
                eprintln!("Error occurred while parsing port!");
                exit(ERROR);
            }
        };

        let size: KeySize = match args[2].parse::<usize>() {
            Ok(128) => KeySize::Size128,
            Ok(192) => KeySize::Size192,
            Ok(256) => KeySize::Size256,
            Ok(_) => {
                eprintln!("Invalid key size! Valid sizes are: 128, 192, 256");
                exit(ERROR);
            }
            Err(_) => {
                eprintln!("Error parsing keysize!");
                exit(ERROR);
            }
        };

        let encryption_type = match args[3].as_str() {
            "AesCbc" => EncryptionInfo::AesCbc,
            "AesCtr" => EncryptionInfo::AesCtr,
            "AesEcb" => EncryptionInfo::AesEcb,
            "Rc4" => EncryptionInfo::Rc4,
            _ => {
                eprintln!("Invalid encryption type!");
                eprintln!("Try --help for help.");
                exit(ERROR);
            }
        };

        let config = KryptosConfig {
            enc_type: encryption_type,
            key_size: size,
            optional_key: match use_key {
                true => Some(args[4].to_string()),
                false => None,
            },
            port,
        };

        config
    }
}
