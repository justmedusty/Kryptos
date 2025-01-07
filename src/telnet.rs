use crate::server_listener::print_vec;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};

pub struct TelnetServerConnection {
    socket_addr: SocketAddr,
    stream: TcpStream,
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
    log: bool,
    log_file: File,
}

pub trait ServerFunctions {
    fn read_from_connection(&mut self) -> usize;
    fn write_to_connection(&mut self) -> usize;
    fn fetch_address(&mut self) -> SocketAddr;
    fn send_closing_message_and_disconnect(&mut self, message: Option<String>);

    fn flush_read_buffer(&mut self);
    fn flush_write_buffer(&mut self);

    fn fill_write_buffer(&mut self, buffer: Vec<u8>);

    fn read_and_print(&mut self);

    fn set_logging(&mut self) -> bool;

    fn set_log_file(&mut self, log_file: String) -> u64;
}

impl ServerFunctions for TelnetServerConnection {
    fn read_from_connection(&mut self) -> usize {
        let ret = self
            .stream
            .read(&mut self.read_buffer)
            .unwrap()
            .max(self.read_buffer.len());
        if (self.log) {
            File::write(&mut self.log_file, &self.read_buffer)
                .expect("Could not write to log file!");
        }
        ret
    }

    fn write_to_connection(&mut self) -> usize {
        self.stream.write(&self.write_buffer).unwrap()
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
        self.read_buffer.clear();
    }

    fn flush_write_buffer(&mut self) {
        self.write_buffer.clear();
    }

    fn fill_write_buffer(&mut self, mut buffer: Vec<u8>) {
        self.write_buffer.append(&mut buffer);
    }

    fn read_and_print(&mut self) {
        while (self.read_from_connection() != 0) {
            print_vec(&self.read_buffer);
        }
    }

    fn set_logging(&mut self) -> bool {
        self.log = !self.log;
        self.log
    }

    fn set_log_file(&mut self, log_file: String) -> u64 {
        let mut file = File::create(&log_file);
        if (file.is_ok()) {
            self.log = true;
            self.log_file = file.unwrap();
            0
        } else {
            println!("Log file {} could not be opened", log_file);
            1
        }
    }
}
