use crate::telnet::{open_telnet_connection, ServerFunctions, TelnetServerConnection};
use std::cell::RefCell;
use std::collections::LinkedList;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::sync::{Arc, RwLock};
use std::thread::sleep;
use std::time::Duration;

mod telnet;

static PORT: u64 = 6969;

type ConnectionPool = Arc<RwLock<LinkedList<Arc<RwLock<TelnetServerConnection>>>>>;
type Connection = Arc<RwLock<TelnetServerConnection>>;

fn broadcast_message(message: Vec<u8>, source: Connection, pool: &ConnectionPool) {
    let pool_ref = pool.read().unwrap();
    let message = RefCell::new(message);
    for connection in pool_ref.iter() {
        let msg = message.borrow();
        let mut connection = connection.write().unwrap();
        print!("HERE\n");
        connection.write_from_passed_buffer(msg.clone());
        drop(connection);
        println!("{}", "HERE");
    }
}

fn spawn_server_thread(connection: Connection, pool: ConnectionPool) {
    std::thread::spawn(move || {
        let mut conn = connection.write().unwrap();
        conn.fill_write_buffer(String::from("HELLO THERE").as_bytes().to_vec());
        conn.write_to_connection();
        loop {
            println!("Entering thread {}", conn.connection_id);

            let val = conn.read_from_connection();
            if val > 0 {
                println!(
                    "Got message on connection {} of size {}",
                    conn.connection_id, val
                );
                broadcast_message(conn.read_buffer.clone(), connection.clone(), &pool.clone());
            }
        }
    });
}

fn spawn_connect_thread() {
    std::thread::spawn(move || {
        println!("Starting client thread");
        loop {
            let mut tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", PORT)).unwrap();
            let mut buf = Box::new([0; 4096]);
            tcp_stream
                .write(&Vec::from(String::from("CLIENT SAYS HELLO\n").as_bytes()))
                .expect("Could not write to tcp output stream");
sleep(Duration::from_secs(1));
            let bytes = tcp_stream
                .read(&mut *buf)
                .expect("Could not read from tcp stream");
            println!(
                "Received a message from the client of size {} byes , contents : {}",
                bytes,
                String::from_utf8(buf[..bytes].to_vec()).as_ref().unwrap()
            );
        }
    });
}

fn main() {
    let mut connection_id = 0;
    let conn_pool = ConnectionPool::new(RwLock::new(Default::default()));
    let server_listener: TcpListener = TcpListener::bind(format!("127.0.0.1:{}", PORT)).unwrap();
    let reference = Arc::new(RwLock::new(server_listener));
    let pool_reference = conn_pool.clone();
    let mut pool = match pool_reference.write() {
        Ok(x) => x,
        Err(_) => panic!("Main thread could not lock RwLock"),
    };
    loop {
        sleep(Duration::new(2, 0));

        sleep(Duration::from_secs(2));
        let curr = Arc::clone(&reference);
        // Accept the connection and handle it if successful
        spawn_connect_thread();
        let mut server_connection = open_telnet_connection(curr, connection_id);
        println!(
            "Accepted connection from {}",
            server_connection.get_address()
        );
        let reference = Arc::new(RwLock::new(server_connection));
        let unwrapped = Arc::clone(&reference);

        pool.push_front(unwrapped);
        connection_id += 1;

        // Spawn a new thread to handle the connection
        spawn_server_thread(reference.clone(), pool_reference.clone());
    }
}
