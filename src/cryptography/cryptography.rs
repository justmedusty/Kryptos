use std::process::Output;

pub trait Encryption {
    fn initialize_context(&mut self);
    fn encrypt(&mut self, input : &[u8] , output: &mut [u8]);
    fn decrypt(&mut self, input : &[u8] , output: &mut [u8]);
    fn set_key(&mut self, key: &[u8] );
}