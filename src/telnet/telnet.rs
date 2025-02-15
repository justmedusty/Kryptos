use crate::arg_handling::arg_handling::arg_handling::{EncryptionInfo, KeySize};
use crate::cryptography::aes::{AESContext, AesMode, AesSize};
use crate::cryptography::cryptography::EncryptionContext;
use crate::cryptography::rc4::Rc4State;
use crate::{GREETING, INVALID_NAME, PORT, SUCCESS_STRING};
use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::ops::DerefMut;
use std::sync::{Arc, RwLock};

pub type ConnectionPool = Arc<RwLock<VecDeque<Connection>>>;
pub type Connection = Arc<RwLock<TelnetServerConnection>>;
pub const VALID_CONNECTION: u64 = 0xFFFFFFFFFFFF;

#[derive(Debug)]
pub struct TelnetServerConnection {
    socket_addr: SocketAddr,
    pub connection_id: u64,
    pub stream: TcpStream,
    pub read_buffer: Vec<u8>,
    pub name: String,
    encryption_context: EncryptionContext,
    log: bool,
    log_file: Option<File>,
}

impl PartialEq<Self> for TelnetServerConnection {
    fn eq(&self, other: &Self) -> bool {
        self.connection_id == other.connection_id
    }
}

impl TelnetServerConnection {
    pub fn new(socket: SocketAddr, connection_id: u64, stream: TcpStream) -> Self {
        let new_connection: TelnetServerConnection = TelnetServerConnection {
            socket_addr: socket,
            connection_id,
            stream,
            read_buffer: vec![0; 1024],
            name: "".to_string(),
            encryption_context: EncryptionContext::new(Rc4State::new(None)),
            log: false,
            log_file: None,
        };

        new_connection
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
    fn write_from_passed_encrypted_buffer(&mut self, buffer: &mut Vec<u8>);
    fn write_from_passed_buffer(&mut self, buffer: &mut Vec<u8>);
    fn fetch_address(&mut self) -> SocketAddr;
    fn send_closing_message_and_disconnect(&mut self, message: Option<String>);

    fn flush_read_buffer(&mut self);

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
            let written = file
                .write(&$self.read_buffer)
                .expect("Could not write to log file!");
        }
    };
}
impl ServerFunctions for TelnetServerConnection {
    // Handle encryption in the write functions with the internal rc4 mechanism
    // Also handle the decryption in the read
    fn read_from_connection(&mut self) -> usize {
        if let Err(_) = self.stream.set_nonblocking(true) {
            return 0;
        }
        let mut encrypted_buffer = vec![0; 1024];

        let ret = match self.stream.read(&mut encrypted_buffer) {
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
        self.read_buffer.resize(ret, 0);
        encrypted_buffer.resize(ret, 0);
        self.encryption_context
            .context
            .decrypt(&mut encrypted_buffer, &mut self.read_buffer);

        write_to_log!(self);
        ret
    }

    fn write_from_passed_encrypted_buffer(&mut self, buffer: &mut Vec<u8>) {
        match self.stream.write_all(&buffer) {
            Ok(x) => x,
            Err(_) => return,
        };
    }

    fn write_from_passed_buffer(&mut self, mut buffer: &mut Vec<u8>) {
        let mut encrypted_buffer = buffer.clone();
        self.encryption_context
            .context
            .encrypt(&mut buffer, &mut encrypted_buffer);
        match self.stream.write_all(&encrypted_buffer) {
            Ok(x) => x,
            Err(_) => return,
        };
    }

    fn fetch_address(&mut self) -> SocketAddr {
        self.socket_addr
    }

    fn send_closing_message_and_disconnect(&mut self, message: Option<String>) {
        self.flush_read_buffer();

        if !message.is_some() {
            self.stream.shutdown(Shutdown::Both).unwrap();
            return;
        }

        let message = message.unwrap();
        self.write_from_passed_buffer(&mut message.as_bytes().to_vec());
        self.flush_read_buffer();
    }

    fn flush_read_buffer(&mut self) {
        for x in &mut self.read_buffer {
            *x = 0;
        }
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

        let mut encrypted_buffer = vec![0; 1024];
        let ret = match self.stream.read(&mut encrypted_buffer) {
            Ok(0) => 0,
            Ok(x) => x,
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset => {
                //Connection was reset (dropped by peer)
                return 0;
            }
            Err(_) => {
                // Other errors, handle appropriately
                return 0;
            }
        };
        println!("READ {ret} BYTES");
        encrypted_buffer.resize(ret, 0);
        self.read_buffer.resize(ret, 0);
        self.encryption_context
            .context
            .decrypt(&mut encrypted_buffer, &mut self.read_buffer);
        write_to_log!(self);
        ret
    }
}
/*
   Open connection sets up a new TelnetServerConnection object with the new connection found on the listener.
*/

pub fn open_telnet_connection(
    listener: Arc<RwLock<TcpListener>>,
    session_key: String,
    encryption_type: EncryptionInfo,
    key_size: KeySize,
) -> TelnetServerConnection {
    let listener = listener.read().unwrap();
    let (tcp_conn, sock_addr) = listener.accept().expect("Failed to accept connection");

    let read_buff = vec![0u8; 4096];
    let new_encryption_context = match encryption_type {
        EncryptionInfo::AesCbc => match key_size {
            KeySize::Size128 => EncryptionContext::new(AESContext::new(
                AesMode::CBC,
                AesSize::S128,
                Some(session_key.as_bytes()),
            )),
            KeySize::Size192 => EncryptionContext::new(AESContext::new(
                AesMode::CBC,
                AesSize::S192,
                Some(session_key.as_bytes()),
            )),
            KeySize::Size256 => EncryptionContext::new(AESContext::new(
                AesMode::CBC,
                AesSize::S256,
                Some(session_key.as_bytes()),
            )),
        },
        EncryptionInfo::AesCtr => match key_size {
            KeySize::Size128 => EncryptionContext::new(AESContext::new(
                AesMode::CTR,
                AesSize::S128,
                Some(session_key.as_bytes()),
            )),
            KeySize::Size192 => EncryptionContext::new(AESContext::new(
                AesMode::CTR,
                AesSize::S192,
                Some(session_key.as_bytes()),
            )),
            KeySize::Size256 => EncryptionContext::new(AESContext::new(
                AesMode::CTR,
                AesSize::S256,
                Some(session_key.as_bytes()),
            )),
        },
        EncryptionInfo::AesEcb => match key_size {
            KeySize::Size128 => EncryptionContext::new(AESContext::new(
                AesMode::ECB,
                AesSize::S128,
                Some(session_key.as_bytes()),
            )),
            KeySize::Size192 => EncryptionContext::new(AESContext::new(
                AesMode::ECB,
                AesSize::S192,
                Some(session_key.as_bytes()),
            )),
            KeySize::Size256 => EncryptionContext::new(AESContext::new(
                AesMode::ECB,
                AesSize::S256,
                Some(session_key.as_bytes()),
            )),
        },
        EncryptionInfo::Rc4 => match key_size {
            KeySize::Size128 => EncryptionContext::new(Rc4State::new(Some(session_key.as_bytes()))),
            KeySize::Size192 => EncryptionContext::new(Rc4State::new(Some(session_key.as_bytes()))),
            KeySize::Size256 => EncryptionContext::new(Rc4State::new(Some(session_key.as_bytes()))),
        },
    };

    let mut server_connection = TelnetServerConnection {
        connection_id: 0,
        stream: tcp_conn,
        socket_addr: sock_addr,
        read_buffer: read_buff,
        name: "".to_string(),
        encryption_context: new_encryption_context,
        log: false,
        log_file: None,
    };

    server_connection
        .encryption_context
        .context
        .set_key(session_key.as_bytes());

    server_connection
}

/*
Broadcast message to every connection in the active pool except the one who sent it
*/

pub fn broadcast_message(message: &mut Vec<u8>, source: u64, pool: &ConnectionPool) {
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
pub fn handle_new_connection(connection: Connection, pool: ConnectionPool) -> bool {
    let mut greeted = false;
    let username: String;

    loop {
        let mut conn = connection.write().unwrap();
        if !greeted {
            conn.write_from_passed_buffer(&mut GREETING.as_bytes().to_vec());
        }

        greeted = true;

        let length = conn.read_from_connection_blocking();

        for byte in conn.read_buffer.iter() {
            if !(*byte).is_ascii() {
                eprintln!("Connection {} on {} is sending invalid ascii, this likely means that they have the wrong session key! Closing connection.",conn.connection_id,conn.socket_addr);
                return false;
            }
        }

        if length == 0 {
            return false;
        }

        let name = String::from_utf8_lossy(&conn.read_buffer)
            .trim()
            .to_string();

        let length = name.len();
        if length > 4 && length < 25 {
            let mut name = name.clone();
            println!("New connection: {}", name);

            conn.write_from_passed_buffer(&mut SUCCESS_STRING.as_bytes().to_vec());

            conn.set_name(name);
            username = conn.name.clone();
            break;
        }

        conn.write_from_passed_buffer(&mut INVALID_NAME.as_bytes().to_vec());
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
    let mut message_vec = message.into_bytes();
    broadcast_message(&mut message_vec, count as u64, &pool);
    true
}

/*
   Main server loop, socket is nonblocking so that it will not stay blocked while inside a locked context (this would break the broadcast function) , broadcasts on leave so others are alerted
*/
pub fn spawn_server_thread(connection: Connection, pool: ConnectionPool) {
    std::thread::spawn(move || {
        let (mut read_buffer, mut connection_id, mut val);
        let result = handle_new_connection(connection.clone(), pool.clone());

        if !result {
            return;
        }

        loop {
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
            drop(conn);

            broadcast_message(&mut read_buffer, connection_id, &pool);

            let mut conn = match connection.write() {
                Ok(x) => x,
                Err(_) => break,
            };
            conn.flush_read_buffer();
            drop(conn);
        }
        let conn_id;
        let name;

        let conn = connection.read().unwrap();
        conn_id = conn.connection_id;
        name = conn.name.clone();
        drop(conn);

        println!("Connection {} closed", conn_id);

        let mut pool_unlocked = pool.write().unwrap();
        pool_unlocked.remove(conn_id as usize);
        drop(pool_unlocked);

        let message = format!("{} has left\n", name);
        let mut message_vec = message.into_bytes();
        broadcast_message(&mut message_vec, conn_id, &pool);
    });
}
/*
This function is just for testing purposes
*/
#[allow(dead_code)]
pub fn spawn_connect_thread() {
    std::thread::spawn(move || {
        println!("Starting client thread");
        let mut tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", PORT)).unwrap();
        let mut buf = Box::new([0; 1024]);
        let write = tcp_stream
            .write(&Vec::from(String::from("TESTBOT\n").as_bytes()))
            .expect("Could not write to tcp output stream");
        loop {
            let read = tcp_stream.read(buf.deref_mut()).unwrap();
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
