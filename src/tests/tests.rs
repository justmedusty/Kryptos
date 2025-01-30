#[cfg(test)]
mod cryptography_tests {
    use crate::cryptography::aes::*;
    use crate::cryptography::cryptography::Encryption;
    use crate::cryptography::rc4::Rc4State;

    macro_rules! generate_ab_arrays {
        ($size:expr) => {{
            let mut input = [0u8; $size];
            let mut output = [0u8; $size];

            for i in 0..$size {
                if i % 2 == 0 {
                    input[i] = b'B';
                    output[i] = b'B';
                } else {
                    input[i] = b'A';
                    output[i] = b'A';
                }
            }

            (input, output)
        }};
    }
    ///This test just ensures that the encryption function does in fact encrypt the plaintext input
    #[test]
    fn test_rc4_encryption() {
        let mut rc4 = Rc4State::new();
        let (input, mut output) = generate_ab_arrays!(256);
        assert_eq!(input, output);
        rc4.encrypt(&input, &mut output);

        assert_ne!(input, output);
    }

    //This test just ensures that the decryption function actually decrypts , and brings back the original plaintext message
    #[test]
    fn test_rc4_decryption() {
        let mut rc4 = Rc4State::new();
        let (mut input, mut output) = generate_ab_arrays!(256);

        let original_input = input.clone();
        rc4.encrypt(&input, &mut output);
        assert_ne!(input, output);
        rc4.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }

    #[test]
    fn test_aes_cbc_encryption_128() {
        let mut aes = AESContext::new(AesMode::CBC, AesSize::S128, None);
        let (input, mut output) = generate_ab_arrays!(256);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);

        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_cbc_decryption_128() {
        let mut aes = AESContext::new(AesMode::CBC, AesSize::S128, None);
        let (mut input, mut output) = generate_ab_arrays!(256);

        let original_input = input.clone();
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);

        assert_ne!(input, output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }

    #[test]
    fn test_aes_ecb_encryption_128() {
        let mut aes = AESContext::new(AesMode::ECB, AesSize::S128, None);
        let (input, mut output) = generate_ab_arrays!(16);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_ecb_decryption_128() {
        let mut aes = AESContext::new(AesMode::ECB, AesSize::S128, None);
        let (mut input, mut output) = generate_ab_arrays!(16);
        let original_input = input.clone();
        aes.encrypt(&input, &mut output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }

    #[test]
    fn test_aes_ctr_encryption_128() {
        let mut aes = AESContext::new(AesMode::CTR, AesSize::S128, None);
        let (input, mut output) = generate_ab_arrays!(256);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_ctr_decryption_128() {
        let mut aes = AESContext::new(AesMode::CTR, AesSize::S128, None);
        let (mut input, mut output) = generate_ab_arrays!(256);
        let original_input = input.clone();
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }
    #[test]
    fn test_aes_cbc_encryption_192() {
        let mut aes = AESContext::new(AesMode::CBC, AesSize::S192, None);
        let (input, mut output) = generate_ab_arrays!(256);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);

        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_cbc_decryption_192() {
        let mut aes = AESContext::new(AesMode::CBC, AesSize::S192, None);
        let (mut input, mut output) = generate_ab_arrays!(256);

        let original_input = input.clone();
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);

        assert_ne!(input, output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }

    #[test]
    fn test_aes_ecb_encryption_192() {
        let mut aes = AESContext::new(AesMode::ECB, AesSize::S192, None);
        let (input, mut output) = generate_ab_arrays!(16);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_ecb_decryption_192() {
        let mut aes = AESContext::new(AesMode::ECB, AesSize::S192, None);
        let (mut input, mut output) = generate_ab_arrays!(16);
        let original_input = input.clone();
        aes.encrypt(&input, &mut output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }

    #[test]
    fn test_aes_ctr_encryption_192() {
        let mut aes = AESContext::new(AesMode::CTR, AesSize::S192, None);
        let (input, mut output) = generate_ab_arrays!(256);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_ctr_decryption_192() {
        let mut aes = AESContext::new(AesMode::CTR, AesSize::S192, None);
        let (mut input, mut output) = generate_ab_arrays!(256);
        let original_input = input.clone();
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }

    #[test]
    fn test_aes_cbc_encryption_256() {
        let mut aes = AESContext::new(AesMode::CBC, AesSize::S256, None);
        let (input, mut output) = generate_ab_arrays!(256);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);

        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_cbc_decryption_256() {
        let mut aes = AESContext::new(AesMode::CBC, AesSize::S256, None);
        let (mut input, mut output) = generate_ab_arrays!(256);

        let original_input = input.clone();
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);

        assert_ne!(input, output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }

    #[test]
    fn test_aes_ecb_encryption_256() {
        let mut aes = AESContext::new(AesMode::ECB, AesSize::S256, None);
        let (input, mut output) = generate_ab_arrays!(16);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_ecb_decryption_256() {
        let mut aes = AESContext::new(AesMode::ECB, AesSize::S256, None);
        let (mut input, mut output) = generate_ab_arrays!(16);
        let original_input = input.clone();
        aes.encrypt(&input, &mut output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }

    #[test]
    fn test_aes_ctr_encryption_256() {
        let mut aes = AESContext::new(AesMode::CTR, AesSize::S256, None);
        let (input, mut output) = generate_ab_arrays!(256);
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
    }

    #[test]
    fn test_aes_ctr_decryption_256() {
        let mut aes = AESContext::new(AesMode::CTR, AesSize::S256, None);
        let (mut input, mut output) = generate_ab_arrays!(256);
        let original_input = input.clone();
        assert_eq!(input, output);
        aes.encrypt(&input, &mut output);
        assert_ne!(input, output);
        aes.decrypt(&output, &mut input);
        assert_eq!(input, original_input);
    }
}
