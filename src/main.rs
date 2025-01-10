use crate::telnet::{open_telnet_connection, ServerFunctions, TelnetServerConnection};
use std::collections::LinkedList;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ops::DerefMut;
use std::sync::{Arc, RwLock};
use std::thread::sleep;
use std::time::Duration;

mod telnet;

static PORT: u64 = 6969;

type ConnectionPool = Arc<RwLock<LinkedList<Connection>>>;
type Connection = Arc<RwLock<TelnetServerConnection>>;

fn broadcast_message(message: &Vec<u8>, source: u64, pool: &ConnectionPool) {
    let pool_ref = pool.read().unwrap();
    let mut num: u64 = 0;
    for connection in pool_ref.iter() {
        let mut conn = RwLock::read(connection).unwrap();
        if conn.connection_id == source {
            drop(conn);
            continue;
        }
        drop(conn);
        let mut conn = RwLock::write(connection).unwrap();
        conn.fill_write_buffer(message.clone()); // Consider moving this outside the loop
        conn.write_to_connection();
        num += 1;
        drop(conn);
    }
    println!("Broadcast done, sent {} messages", num);
}

fn spawn_server_thread(connection: Connection, pool: ConnectionPool) {
    std::thread::spawn(move || {
            let (read_buffer, connection_id, val);

            {
                let mut conn = connection.write().unwrap();
                println!("Entering thread {}", conn.connection_id);
                connection_id = conn.connection_id;
                val = conn.read_from_connection();
                if val > 0 {
                    read_buffer = conn.read_buffer.clone();
                    println!(
                        "Got message on connection {} of size {}",
                        conn.connection_id, val
                    );
                    conn.flush_read_buffer();
                } else {
                    return;
                }
            }

            broadcast_message(&read_buffer, connection_id, &pool);

    });
}
fn spawn_connect_thread() {
    std::thread::spawn(move || {
        println!("Starting client thread");
        let mut tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", PORT)).unwrap();
        let mut buf = Box::new([0; 4096]);
        tcp_stream
            .write(&Vec::from(String::from("CLIENT SAYS HELLO\n").as_bytes()))
            .expect("Could not write to tcp output stream");
        sleep(Duration::from_secs(2));

        match tcp_stream.read(buf.deref_mut()) {
            Ok(x) => x,
            Err(_) => panic!("Could not read from tcp stream"),
        };

        println!(
            "Received a message from the client {}",
            String::from_utf8(buf.to_vec()).unwrap()
        );

    });
}

fn main() {
    let mut connection_id = 0;
    let conn_pool = ConnectionPool::new(RwLock::new(Default::default()));
    let server_listener: TcpListener = TcpListener::bind(format!("127.0.0.1:{}", PORT)).unwrap();
    let reference = Arc::new(RwLock::new(server_listener));
    let pool_reference = conn_pool.clone();

    loop {
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
        let mut pool = pool_reference.write().unwrap();
        pool.push_front(unwrapped);
        drop(pool);
        connection_id += 1;

        // Spawn a new thread to handle the connection
        spawn_server_thread(Arc::clone(&reference), Arc::clone(&pool_reference));
        drop(reference);

        sleep(Duration::new(2, 0));
    }
}
