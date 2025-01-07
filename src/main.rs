use crate::server_listener::{open_connection, Server, ServerConnection};
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::sleep;
use std::time::Duration;

mod server_listener;
mod telnet;

static PORT: u64 = 6969;

fn spawn_server_thread(connection: Arc<Mutex<ServerConnection>>) {
    let thread = std::thread::spawn(move || {
        let mut curr = connection.lock().unwrap();
        loop {
            sleep(Duration::new(1, 0));

            let hello_msg = String::from("hello world");
            curr.fill_write_buffer(&Vec::from(hello_msg.as_bytes()));
            curr.send();
            curr.read();
            curr.print_buffer();
            break;
        }
    });
}


fn spawn_connect_thread() {
    let thread = std::thread::spawn(move || loop {
        sleep(Duration::from_secs(3));
        let mut tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", PORT)).unwrap();
        tcp_stream.write(&Vec::from(String::from("CLIENT SAYS HELLO").as_bytes())).expect("Could not write to tcp output stream");
        tcp_stream.flush().unwrap();
    });
}
fn main() {
    let server_listener: TcpListener = TcpListener::bind(format!("127.0.0.1:{}", PORT)).unwrap();
    let reference = Arc::new(Mutex::new(server_listener));

    loop {
        let curr = Arc::clone(&reference);
        println!("Trying connection...");

        // Accept the connection and handle it if successful
        spawn_connect_thread();
        let server_connection = open_connection(curr);

        println!("Accepted connection from {}", server_connection.get_addr());
        // Spawn a new thread to handle the connection
        spawn_server_thread(Arc::new(Mutex::new(server_connection)));

        sleep(Duration::new(1, 0));
        println!("Looping");
    }
}
