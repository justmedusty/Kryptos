
use rand::distr::Alphanumeric;
use rand::Rng;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ops::{DerefMut};
use std::sync::{Arc, RwLock};
use telnet::{open_telnet_connection, ServerFunctions, TelnetServerConnection, VALID_CONNECTION};

mod telnet;
mod cryptography;
mod tests;

static PORT: u64 = 6969;

const GREETING: &'static str = "Welcome to the server, what will your username be? :";
const INVALID_NAME: &'static str = "That is not a valid username. What will your username be? :";
const SUCCESS_STRING: &'static str = "Username is valid, joining session\n";

type ConnectionPool = Arc<RwLock<VecDeque<Connection>>>;
type Connection = Arc<RwLock<TelnetServerConnection>>;

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
Broadcast message to every connection in the active pool except the one who sent it
*/

fn broadcast_message(message: &Vec<u8>, source: u64, pool: &ConnectionPool) {
    let pool_ref = pool.read().unwrap();

    for connection in pool_ref.iter() {
        let mut conn = match connection.write() {
            Ok(x) => x,
            Err(_) => continue,
        };

        if conn.connection_id == source {
            continue;
        }

        conn.write_from_passed_buffer(message);
    }
}

/*
Handle grabbing the username of the new connection, must be between 5 and 25 characters long
Sets up the connection with the username provided and inserts it into the connection pool before returning into the main server thread loop
*/
fn handle_new_connection(connection: Connection, pool: ConnectionPool) {
    let mut greeted = false;
    let username: String;

    loop {
        let mut conn = connection.write().unwrap();
        if !greeted {
            conn.fill_write_buffer(Vec::from(GREETING.trim().as_bytes()));
            conn.write_to_connection();
        }

        greeted = true;

        let length = conn.read_from_connection_blocking();

        if length == 0 {
            return;
        }

        let name = String::from_utf8_lossy(&*conn.read_buffer.to_vec())
            .trim()
            .to_string();
        conn.flush_read_buffer();

        if length > 4 && length < 25 {
            println!("New connection: {}", name);
            conn.fill_write_buffer(Vec::from(SUCCESS_STRING));
            conn.write_to_connection();
            let mut name = name.clone();
            name.truncate(length);
            conn.set_name(name);
            username = conn.name.clone();
            break;
        }

        conn.fill_write_buffer(Vec::from(INVALID_NAME));
        conn.write_to_connection();
    }
    /*
       Once user has provided a valid username we will insert into the pool and broadcast a message to all other connected parties
    */
    let count;

    /*
       Put the bottom two snippets in their own scope block so as to keep the lock/unlock timing from blocking too much should somewhere else need to access the connection or pool
    */
    {
        let mut pool_ref = pool.write().unwrap();
        count = pool_ref.iter().count();
        pool_ref.insert(count, connection.clone());
    }

    {
        let mut conn = connection.write().unwrap();
        conn.connection_id = count as u64;
    }

    let message = format!("{} has joined\n", username);
    let message_vec = message.into_bytes();
    broadcast_message(&message_vec, count as u64, &pool);
    return;
}
/*
   Main server loop, socket is nonblocking so that it will not stay blocked while inside a locked context (this would break the broadcast function) , broadcasts on leave so others are alerted
*/
fn spawn_server_thread(connection: Connection, pool: ConnectionPool) {
    std::thread::spawn(move || loop {
        let (mut read_buffer, mut connection_id, mut val);
        handle_new_connection(connection.clone(), pool.clone());
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
                    read_buffer.resize(val, 0);
                    let mut prefix = conn.name.clone().into_bytes();
                    prefix.push(b':');
                    prefix.push(b' ');
                    prefix.extend_from_slice(&read_buffer);
                    prefix.push(b'\n');
                    read_buffer = prefix;
                } else if val == VALID_CONNECTION as usize {
                    continue;
                } else if val == 0 {
                    break;
                } else {
                    continue;
                }
            }
            broadcast_message(&read_buffer, connection_id, &pool);

            {
                let mut conn = match connection.write() {
                    Ok(x) => x,
                    Err(_) => break,
                };
                conn.flush_read_buffer();
            }
        }
        let conn_id;
        let name;
        {
            let conn = connection.read().unwrap();
            conn_id = conn.connection_id;
            name = conn.name.clone();
        }

        println!("Connection {} closed", conn_id);

        {
            let mut pool = pool.write().unwrap();
            pool.remove(conn_id as usize);
        }
        let message = format!("{} has left\n", name);
        let message_vec = message.into_bytes();
        broadcast_message(&message_vec, conn_id, &pool);
        return;
    });
}
/*
This function is just for testing purposes
*/#[allow(dead_code)]
fn spawn_connect_thread() {
    std::thread::spawn(move || loop {
        println!("Starting client thread");
        let mut tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", PORT)).unwrap();
        let mut buf = Box::new([0; 1024]);
        tcp_stream
            .write(&Vec::from(String::from("TESTBOT\n").as_bytes()))
            .expect("Could not write to tcp output stream");
        loop {
            tcp_stream.read(buf.deref_mut()).unwrap();
            if buf[0] != b'\0' {
                println!(
                    "Received a message from the server : {}",
                    String::from_utf8(buf.to_vec()).unwrap()
                );

                buf.iter_mut().for_each(|x| *x = 0);
            }
        }
    });
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
