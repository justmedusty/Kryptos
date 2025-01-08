use crate::telnet::{open_telnet_connection, ServerFunctions, TelnetServerConnection};
use std::collections::LinkedList;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

mod telnet;

static PORT: u64 = 6969;

type ConnectionPool = Arc<Mutex<LinkedList<Arc<Mutex<TelnetServerConnection>>>>>;
type Connection = Arc<Mutex<TelnetServerConnection>>;

fn broadcast_message(message: &Vec<u8>, source: &Connection, pool: &ConnectionPool) {
    let pool_ref = pool.lock().unwrap();
    for connection in pool_ref.iter() {
        /*
        if connection.as_ref() == source.as_ref() {
            continue;
        }
        */

        let mut connection = connection.lock().unwrap();
        connection.fill_write_buffer(message.clone());
        connection.write_to_connection();
    }
}

fn spawn_server_thread(
    connection: Connection,
    pool: ConnectionPool,
) {
    std::thread::spawn(move || loop {
        let mut curr = connection.lock().unwrap();
        if curr.read_from_connection() != 0 {
            curr.read_and_print();
            broadcast_message(&curr.read_buffer.clone(), &connection, &pool);
        }
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
    let mut conn_pool = ConnectionPool::new(Mutex::new(Default::default()));
    let server_listener: TcpListener = TcpListener::bind(format!("127.0.0.1:{}", PORT)).unwrap();
    let reference = Arc::new(Mutex::new(server_listener));
    let cloned_reference = conn_pool.clone();

    loop {
        let mut pool = cloned_reference.lock().unwrap();
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
        let unwrapped = Arc::clone(&reference);

        pool.push_front(unwrapped);
        connection_id += 1;

        let passed_ref = Arc::clone(&reference);
        // Spawn a new thread to handle the connection
        spawn_server_thread(passed_ref, cloned_reference.clone());

        sleep(Duration::new(2, 0));
    }
}
