use crate::telnet::{open_telnet_connection, ServerFunctions, TelnetServerConnection};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ops::DerefMut;
use std::sync::{Arc, RwLock};
use std::thread::sleep;
use std::time::Duration;

mod telnet;

static PORT: u64 = 6969;

type ConnectionPool = Arc<RwLock<VecDeque<Connection>>>;
type Connection = Arc<RwLock<TelnetServerConnection>>;

fn broadcast_message(message: &Vec<u8>, source: u64, pool: &ConnectionPool) {
    let connections: Vec<_>;

    {
        let pool_ref = pool.read().unwrap();
        connections = pool_ref.iter().cloned().collect();
    }
    print!("Size is {}\n", connections.len());
    let mut num: u64 = 0;

    for connection in connections {
        let mut dest: u64 = 0;

        let mut conn = connection.write().unwrap();
        if conn.connection_id == source {
            continue;
        }
        dest = conn.connection_id;

        println!("Sending message from {} to {}", source, dest);
        conn.fill_write_buffer(message.clone());
        if conn.write_to_connection() == 0 {
            {
                let mut pool = pool.write().unwrap();
                println!("DELETING NODE!");
                pool.remove(conn.connection_id as usize);
                continue;
            }
        }
    }
    num += 1;

println!("Broadcast done, sent {} messages", num);
}

fn spawn_server_thread(connection: Connection, pool: ConnectionPool) {
    std::thread::spawn(move || loop {
        loop {
            let (read_buffer, connection_id, val);

            {
                let mut conn = connection.write().unwrap();
                connection_id = conn.connection_id;
                val = conn.read_from_connection();
                if val > 0 && val != 0xFFFFFFFFFFFF {
                    read_buffer = conn.read_buffer.clone();
                    conn.flush_read_buffer();
                } else {
                    return;
                }
            }

            broadcast_message(&read_buffer, connection_id, &pool);
        }
    });
}
fn spawn_connect_thread() {
    std::thread::spawn(move || loop {
        println!("Starting client thread");
        let mut tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", PORT)).unwrap();
        let mut buf = Box::new([0; 1024]);
        tcp_stream
            .write(&Vec::from(String::from("CLIENT SAYS HELLO\n").as_bytes()))
            .expect("Could not write to tcp output stream");

        tcp_stream.read(buf.deref_mut()).unwrap();

        println!(
            "Received a message from the server : {}",
            String::from_utf8(buf.to_vec()).unwrap()
        );
    });
}

fn main() {
    let mut connection_id = 0;
    let conn_pool = ConnectionPool::new(RwLock::new(Default::default()));
    let server_listener: TcpListener = TcpListener::bind(format!("127.0.0.1:{}", PORT)).unwrap();
    let reference = Arc::new(RwLock::new(server_listener));
    let pool_reference = Arc::clone(&conn_pool);

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

        {
            let mut pool = pool_reference.write().unwrap();
            let count = pool.iter().count();
            pool.insert(count, reference);
        }

        connection_id += 1;

        // Spawn a new thread to handle the connection
        spawn_server_thread(Arc::clone(&unwrapped), Arc::clone(&pool_reference));

        sleep(Duration::new(2, 0));
    }
}
