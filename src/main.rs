use crate::telnet::{spawn_server_thread, ConnectionPool};
use rand::distr::Alphanumeric;
use rand::Rng;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::ops::DerefMut;
use std::sync::{Arc, RwLock};
use telnet::{open_telnet_connection, ServerFunctions};

mod cryptography;
mod telnet;
mod tests;

static PORT: u64 = 6969;

const GREETING: &'static str = "Welcome to the server, what will your username be? :";
const INVALID_NAME: &'static str = "That is not a valid username. What will your username be? :";
const SUCCESS_STRING: &'static str = "Username is valid, joining session\n";

/*
   This is not being used yet but can be used to implement a very basic auth mechanism.
*/
fn generate_session_token() -> String {
    // Generate a random alphanumeric string
    let len = 64;
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
    let session_token = generate_session_token();
    println!("Starting telnet server...");
    println!("Session token: {}", session_token);
    let conn_pool = ConnectionPool::new(RwLock::new(Default::default()));
    let server_listener: TcpListener = TcpListener::bind(format!("0.0.0.0:{}", PORT)).unwrap();
    let reference = Arc::new(RwLock::new(server_listener));
    let pool_reference = Arc::clone(&conn_pool);

    loop {
        let curr = Arc::clone(&reference);

        let mut server_connection = open_telnet_connection(curr, 0 /* Placeholder value */);

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
