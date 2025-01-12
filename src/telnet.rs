use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::exit;
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub(crate) static VALID_CONNECTION : u64= 0xFFFFFFFFFFFF;
#[derive(Debug)]
pub struct TelnetServerConnection {
    socket_addr: SocketAddr,
    pub connection_id: u64,
    pub stream: TcpStream,
    pub read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
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
}

impl ServerFunctions for TelnetServerConnection {
    fn read_from_connection(&mut self) -> usize {
        if let Err(_) = self.stream.set_nonblocking(true){
            return 0;
        }
        let ret = match self.stream.read(&mut self.read_buffer) {
            Ok(0) => {
                return VALID_CONNECTION as usize;
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

        if self.log && self.log_file.is_some() {
            let file = self.log_file.as_ref().unwrap();
            let reference = Arc::new(RwLock::new(file));
            let mut file = reference.write().unwrap();
            file.write(&self.read_buffer)
                .expect("Could not write to log file!");
        }
        ret
    }

    fn write_from_passed_buffer(&mut self, buffer: &Vec<u8>) {
        match self.stream.write_all(buffer.as_ref()) {
            Ok(x) => x,
            Err(_) => exit(1),
        };
    }

    fn write_to_connection(&mut self) {
        match self.stream
            .write_all(&self.write_buffer) {
            Ok(x) => x,
            Err(_) => exit(1),
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
        self.read_buffer.iter().for_each(|mut x| x = &b'\0');;
    }

    fn flush_write_buffer(&mut self) {
        self.write_buffer.iter().for_each(|mut x| x = &b'\0');
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
}

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
        log: false,
        log_file: None,
    };

    server_connection
}
