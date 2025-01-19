use std::collections::VecDeque;
use crate::{ GREETING, INVALID_NAME, PORT, SUCCESS_STRING};
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::ops::DerefMut;
use std::sync::{Arc, RwLock};

pub type ConnectionPool = Arc<RwLock<VecDeque<Connection>>>;
pub type Connection = Arc<RwLock<TelnetServerConnection>>;
pub static VALID_CONNECTION: u64 = 0xFFFFFFFFFFFF;
#[derive(Debug)]
pub struct TelnetServerConnection {
    socket_addr: SocketAddr,
    pub connection_id: u64,
    pub stream: TcpStream,
    pub read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
    pub name: String,
    log: bool,
    log_file: Option<File>,
}

impl PartialEq<Self> for TelnetServerConnection {
    fn eq(&self, other: &Self) -> bool {
        self.connection_id == other.connection_id
    }
}

pub fn print_vec(buffer: &[u8]) {
    for byte in buffer {
        if *byte != b'\0' {
            print!("{}", *byte as char);
        } else {
            return;
        }
    }
}
pub trait ServerFunctions {
    fn read_from_connection(&mut self) -> usize;
    fn write_from_passed_buffer(&mut self, buffer: &Vec<u8>);
    fn write_to_connection(&mut self);
    fn fetch_address(&mut self) -> SocketAddr;
    fn send_closing_message_and_disconnect(&mut self, message: Option<String>);

    fn flush_read_buffer(&mut self);
    fn flush_write_buffer(&mut self);

    fn fill_write_buffer(&mut self, buffer: Vec<u8>);

    fn read_and_print(&mut self);

    fn set_logging(&mut self) -> bool;

    fn set_log_file(&mut self, log_file: String) -> u64;

    fn get_address(&mut self) -> SocketAddr;

    fn set_name(&mut self, name: String) -> u64;

    fn read_from_connection_blocking(&mut self) -> usize;
}
macro_rules! write_to_log {
    ($self:expr) => {
        if $self.log && $self.log_file.is_some() {
            let file = $self.log_file.as_ref().unwrap();
            let reference = Arc::new(RwLock::new(file));
            let mut file = reference.write().unwrap();
            file.write(&$self.read_buffer)
                .expect("Could not write to log file!");
        }
    };
}
impl ServerFunctions for TelnetServerConnection {
    fn read_from_connection(&mut self) -> usize {
        if let Err(_) = self.stream.set_nonblocking(true) {
            return 0;
        }
        let ret = match self.stream.read(&mut self.read_buffer) {
            Ok(0) => {
                return 0;
            }
            Ok(x) => x,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No data available now, return immediately
                return VALID_CONNECTION as usize;
            }
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset => {
                // Connection was reset (dropped by peer)
                return 0;
            }
            Err(_) => {
                // Other errors, handle appropriately
                return 0;
            }
        };

        write_to_log!(self);
        ret
    }

    fn write_from_passed_buffer(&mut self, buffer: &Vec<u8>) {
        match self.stream.write_all(buffer.as_ref()) {
            Ok(x) => x,
            Err(_) => return,
        };
    }

    fn write_to_connection(&mut self) {
        match self.stream.write_all(&self.write_buffer) {
            Ok(x) => x,
            Err(_) => return,
        };
        self.flush_write_buffer();
    }

    fn fetch_address(&mut self) -> SocketAddr {
        self.socket_addr
    }

    fn send_closing_message_and_disconnect(&mut self, message: Option<String>) {
        self.flush_read_buffer();
        self.flush_write_buffer();

        if !message.is_some() {
            self.stream.shutdown(Shutdown::Both).unwrap();
            return;
        }

        let message = message.unwrap();
        self.write_buffer.append(&mut message.into_bytes());
        self.write_to_connection();
        self.flush_read_buffer();
        self.flush_write_buffer();
    }

    fn flush_read_buffer(&mut self) {
        for x in &mut self.read_buffer {
            *x = 0;
        }
    }

    fn flush_write_buffer(&mut self) {
        for x in &mut self.write_buffer {
            *x = 0;
        }
    }

    fn fill_write_buffer(&mut self, mut buffer: Vec<u8>) {
        self.write_buffer.append(&mut buffer);
    }

    fn read_and_print(&mut self) {
        self.read_from_connection();
        print_vec(&self.read_buffer);
    }

    fn set_logging(&mut self) -> bool {
        self.log = !self.log;
        self.log
    }

    fn set_log_file(&mut self, log_file: String) -> u64 {
        let file = File::create(&log_file);
        if file.is_ok() {
            self.log = true;
            self.log_file = Option::from(file.unwrap());
            0
        } else {
            println!("Log file {} could not be opened", log_file);
            1
        }
    }

    fn get_address(&mut self) -> SocketAddr {
        self.socket_addr
    }

    fn set_name(&mut self, name: String) -> u64 {
        if name.is_empty() || name == "" {
            return 0;
        }
        let ret = name.len() as u64;
        self.name = name;
        ret
    }

    fn read_from_connection_blocking(&mut self) -> usize {
        if let Err(_) = self.stream.set_nonblocking(false) {
            return 0;
        }
        let ret = match self.stream.read(&mut self.read_buffer) {
            Ok(0) => 0,
            Ok(x) => x,
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset => {
                // Connection was reset (dropped by peer)
                return 0;
            }
            Err(_) => {
                // Other errors, handle appropriately
                return 0;
            }
        };

        write_to_log!(self);
        ret
    }
}
/*
   Open connection sets up a new TelnetServerConnection object with the new connection found on the listener.
*/
pub fn open_telnet_connection(
    listener: Arc<RwLock<TcpListener>>,
    conn_id: u64,
) -> TelnetServerConnection {
    let listener = listener.read().unwrap();
    let (tcp_conn, sock_addr) = listener.accept().expect("Failed to accept connection");

    let read_buff = vec![0u8; 4096];
    let write_buff = vec![0u8; 4096];

    let server_connection = TelnetServerConnection {
        connection_id: conn_id,
        stream: tcp_conn,
        socket_addr: sock_addr,
        read_buffer: read_buff,
        write_buffer: write_buff,
        name: "".to_string(),
        log: false,
        log_file: None,
    };

    server_connection
}

/*
Broadcast message to every connection in the active pool except the one who sent it
*/

pub fn broadcast_message(message: &Vec<u8>, source: u64, pool: &ConnectionPool) {
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
pub fn handle_new_connection(connection: Connection, pool: ConnectionPool) {
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
pub fn spawn_server_thread(connection: Connection, pool: ConnectionPool) {
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
*/
#[allow(dead_code)]
pub fn spawn_connect_thread() {
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