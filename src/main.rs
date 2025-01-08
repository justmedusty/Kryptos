use crate::telnet::{open_telnet_connection, ServerFunctions, TelnetServerConnection};
use std::collections::LinkedList;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

mod telnet;

static PORT: u64 = 6969;

type ConnectionPool = LinkedList<Arc<Mutex<TelnetServerConnection>>>;

fn spawn_server_thread(connection: Arc<Mutex<TelnetServerConnection>>) {
    std::thread::spawn(move || {
        let mut curr = connection.lock().unwrap();
        sleep(Duration::new(5, 0));
        curr.read_and_print();
    });
}

fn spawn_connect_thread() {
    std::thread::spawn(move || {
        println!("Starting client thread");

        let mut tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", PORT)).unwrap();
        tcp_stream
            .write(&Vec::from(String::from("CLIENT SAYS HELLO\n").as_bytes()))
            .expect("Could not write to tcp output stream");
        sleep(Duration::from_secs(5));
    });
}
fn main() {
    let mut connection_id = 0;
    let mut conn_pool = ConnectionPool::new();
    let server_listener: TcpListener = TcpListener::bind(format!("127.0.0.1:{}", PORT)).unwrap();
    let reference = Arc::new(Mutex::new(server_listener));

    loop {
        sleep(Duration::from_secs(2));
        let curr = Arc::clone(&reference);
        println!("Trying connection...");

        // Accept the connection and handle it if successful
        spawn_connect_thread();
        let mut server_connection = open_telnet_connection(curr, connection_id);
        println!(
            "Accepted connection from {}",
            server_connection.get_address()
        );
        let reference = Arc::new(Mutex::new(server_connection));
        let open_ref = Arc::clone(&reference);
        conn_pool.push_front(open_ref);
        connection_id += 1;

        let passed_ref = Arc::clone(&reference);
        // Spawn a new thread to handle the connection
        spawn_server_thread(passed_ref);

        sleep(Duration::new(10, 0));
    }
}
