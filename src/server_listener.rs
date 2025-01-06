use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};

static CONN_ID: AtomicU64 = AtomicU64::new(0);
pub struct ServerConnection {
    tcp_stream: TcpStream,
    socket_addr: SocketAddr,
    conn_id: u64,
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
    is_in_use: AtomicBool,
}

pub trait Listen {
    fn read(&mut self) -> usize;
    fn close(&mut self);
    fn send(&mut self) -> usize;

    fn fill_write_buffer(&mut self, bytes: &Vec<u8>);

    fn fill_read_buffer(&mut self, bytes: &Vec<u8>);

    fn get_addr(&self) -> SocketAddr;

    fn print_buffer(&mut self);
}

fn print_vec(bytes: &Vec<u8>) {
    for b in bytes {
        if (*b == b'\0') {
            return;
        }
        print!("{}", *b as char);
    }
}
impl Listen for ServerConnection {
    fn read(&mut self) -> usize {
        return self
            .tcp_stream
            .read(&mut self.read_buffer)
            .expect("Failed to read data from server connection");
    }

    fn close(&mut self) {
        self.tcp_stream
            .shutdown(Shutdown::Both)
            .expect("Failed to close server connection");
    }

    fn send(&mut self) -> usize {
        return self
            .tcp_stream
            .write(&self.write_buffer)
            .expect("Failed to write to server connection");
    }

    fn fill_read_buffer(&mut self, bytes: &Vec<u8>) {
        self.read_buffer.write_all(bytes).unwrap();
    }

    fn fill_write_buffer(&mut self, bytes: &Vec<u8>) {
        self.write_buffer.write_all(bytes).unwrap();
    }

    fn get_addr(&self) -> SocketAddr {
        return self.socket_addr;
    }

    fn print_buffer(&mut self) {
        print_vec(&self.read_buffer);
        println!("");
    }
}

pub fn open_connection(listener: Arc<Mutex<TcpListener>>) -> ServerConnection {
    let listener = listener.lock().unwrap();
    let (tcp_conn, sock_addr) = listener.accept().unwrap();
    let connection = CONN_ID.fetch_add(1, SeqCst);
    let read_buff = vec![0u8; 4096];
    let write_buff = vec![0u8; 4096];

    let server_connection = ServerConnection {
        conn_id: connection,
        tcp_stream: tcp_conn,
        socket_addr: sock_addr,
        read_buffer: read_buff,
        write_buffer: write_buff,
        is_in_use: AtomicBool::new(false),
    };

    server_connection
}
