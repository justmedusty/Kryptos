use rand::{rng,RngCore};

struct Rc4State {
    input: Vec<u8>,
    output: Vec<u8>,
    key: Rc4Key,
}

struct Rc4Key {
    key: [u8; 256],
}

impl Rc4State {
    fn generate_key(&mut self){
        let mut key =[0u8; 256];

        rng().fill_bytes(&mut key);

        self.key.key = key;
    }


    fn encrypt(&mut self, input: &[u8],output: &mut [u8]) {

    }


    fn decrypt(&mut self, input: &[u8],output: &mut [u8]) {

    }






}
