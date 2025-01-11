use crate::telnet::{
    open_telnet_connection, ServerFunctions, TelnetServerConnection, VALID_CONNECTION,
};
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
    let mut num: u64 = 0;

    for connection in connections {
        let mut dest: u64 = 0;

        let mut conn = match connection.write() {
            Ok(x) => x,
            Err(_) => continue,
        };

        if conn.connection_id == source {
            continue;
        }
        dest = conn.connection_id;
        conn.write_from_passed_buffer(message);
    }
    num += 1;
}

fn spawn_server_thread(connection: Connection, pool: ConnectionPool) {
    std::thread::spawn(move || loop {
        let (mut read_buffer, mut connection_id, mut val);

        loop {
            {
                let mut conn = match connection.write() {
                    Ok(x) => x,
                    Err(_) => break,
                };

                connection_id = conn.connection_id;
                val = conn.read_from_connection();

                if val > 0 && val != VALID_CONNECTION as usize {
                    read_buffer = conn.read_buffer.clone();
                    conn.flush_read_buffer();
                } else if val == VALID_CONNECTION as usize {
                    continue;
                } else if val == 0 {
                    {
                        let mut pool = pool.write().unwrap();
                        println!("Connection {} closed", conn.connection_id);
                        pool.remove(conn.connection_id as usize);
                    }

                    broadcast_message(
                        &String::from("User has left").into_bytes(),
                        conn.connection_id,
                        &pool,
                    );

                    return;
                } else {
                    continue;
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
        loop {
            let read =tcp_stream.read(buf.deref_mut()).unwrap();
            if(buf[0] != b'\0'){
                println!(
                    "Received a message from the server : {}",
                    String::from_utf8(buf.to_vec()).unwrap()
                );

                buf.iter_mut().for_each(|x| *x = 0);
            }

        }
    });
}

fn main() {
    let mut connection_id = 0;
    let conn_pool = ConnectionPool::new(RwLock::new(Default::default()));
    let server_listener: TcpListener = TcpListener::bind(format!("127.0.0.1:{}", PORT)).unwrap();
    let reference = Arc::new(RwLock::new(server_listener));
    let pool_reference = Arc::clone(&conn_pool);
    for i in 0..15{
        spawn_connect_thread();
    }


    loop {
        let curr = Arc::clone(&reference);

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
    }
}
