use crate::arg_handling::arg_handling::arg_handling::{parse_arguments, KeySize};
use crate::cryptography::rc4::KEY_SIZE_BYTES;
use crate::telnet::{spawn_server_thread, ConnectionPool};
use rand::distr::Alphanumeric;
use rand::Rng;
use std::env;
use std::net::TcpListener;
use std::sync::{Arc, RwLock};
use telnet::{open_telnet_connection, ServerFunctions};
/*
   Declare submodules
*/
mod arg_handling;
mod cryptography;
mod telnet;
mod tests;

static PORT: u64 = 6969;

const ERROR: i32 = 1;
const SUCCESS: i32 = 0;
const GREETING: &'static str = "Welcome to the server, what will your username be? :";
const INVALID_NAME: &'static str = "That is not a valid username. What will your username be? :";
const SUCCESS_STRING: &'static str = "Username is valid, joining session\n";

/*
   This is not being used yet but can be used to implement a very basic auth mechanism.
*/
fn generate_session_token() -> String {
    // Generate a random alphanumeric string
    let len = KEY_SIZE_BYTES;
    let random_string: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect();

    random_string
}

/*
   Main loop, binds to all addresses possible, listens for connections and spawns threads on each new connection
*/
fn main() {
    let mut port = 0;
    let args: Vec<String> = env::args().collect();
    let config = parse_arguments(args);
    let mut session_token: String;

    /*
       Key will be validated inside parse_arguments function
    */
    match config.optional_key {
        None => {
            session_token = generate_session_token();
            let key_size: usize = <KeySize as Into<usize>>::into(config.key_size) / 8;
            session_token.truncate(key_size);
        }
        Some(ref key) => {
            session_token = key.clone();
        }
    }
    port = config.port;
    let key_size = config.key_size;
    let encryption_type = config.enc_type;
    println!("Starting telnet server...");
    println!("Session key: {}", session_token);
    let conn_pool = ConnectionPool::new(RwLock::new(Default::default()));
    let server_listener: TcpListener = TcpListener::bind(format!("0.0.0.0:{}", PORT)).unwrap();
    let reference = Arc::new(RwLock::new(server_listener));
    let pool_reference = Arc::clone(&conn_pool);

    loop {
        let curr = Arc::clone(&reference);

        let mut server_connection =
            open_telnet_connection(curr, session_token.clone(), encryption_type, key_size);

        println!(
            "Accepted connection from {}",
            server_connection.get_address()
        );
        let reference = Arc::new(RwLock::new(server_connection));
        let unwrapped = Arc::clone(&reference);

        // Spawn a new thread to handle the connection

        spawn_server_thread(Arc::clone(&unwrapped), Arc::clone(&pool_reference));
    }
}
