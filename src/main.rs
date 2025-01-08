
use crate::telnet::{open_telnet_connection, ServerFunctions, TelnetServerConnection};
use std::io::{stdout, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::sleep;
use std::time::Duration;

mod telnet;

static PORT: u64 = 6969;

type ConnectionPool = Vec<Arc<Mutex<TelnetServerConnection>>>;

fn spawn_server_thread(connection: Arc<Mutex<TelnetServerConnection>>) {
    let thread = std::thread::spawn(move || {
        let mut curr = connection.lock().unwrap();
            sleep(Duration::new(5, 0));
            curr.read_and_print();

    });
}

fn spawn_connect_thread() {
    let thread = std::thread::spawn(move ||{
        println!("Starting client thread");

        let mut tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", PORT)).unwrap();
        tcp_stream.write(&Vec::from(String::from("CLIENT SAYS HELLO\n").as_bytes())).expect("Could not write to tcp output stream");
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
        connection_id +=1;
        println!("Accepted connection from {}", server_connection.get_address());
        // Spawn a new thread to handle the connection
        spawn_server_thread(Arc::new(Mutex::new(server_connection)));

        sleep(Duration::new(10, 0));
    }
}
