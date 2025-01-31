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
/*
    Standard tests below
 */
    #[test]
    fn test_ecb_encrypt_standard_test_case_128() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ];
        let plaintext = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
        ];
        let expected_ciphertext = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
        ];
        let mut ciphertext = [0u8; 16];

        let mut context = AESContext::new(AesMode::ECB, AesSize::S128, Some(&key));
        context.encrypt(&plaintext, &mut ciphertext);

        assert_eq!(ciphertext, expected_ciphertext);
    }

    #[test]
    fn test_ecb_encrypt_standard_test_case_192() {
        let key = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
            0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
        ];
        let expected_ciphertext = [
            0xbd, 0x33, 0x4f, 0x4c, 0xa8, 0x1f, 0x8b, 0x75,
            0x6d, 0xd4, 0x77, 0xa8, 0x6a, 0x41, 0x41, 0x67
        ];
        let mut ciphertext = [0u8; 16];

        let mut context = AESContext::new(AesMode::ECB, AesSize::S192, Some(&key));
        context.encrypt(&plaintext, &mut ciphertext);

        assert_eq!(ciphertext, expected_ciphertext);
    }

    #[test]
    fn test_ecb_encrypt_standard_test_case_256() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
        ];
        let expected_ciphertext = [
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
            0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
        ];
        let mut ciphertext = [0u8; 16];

        let mut context = AESContext::new(AesMode::ECB, AesSize::S256, Some(&key));
        context.encrypt(&plaintext, &mut ciphertext);

        assert_eq!(ciphertext, expected_ciphertext);
    }

    /*
        This test just prints the keys and I manually examined them, they look good so key scheduling is correct
     */
    #[test]
    fn round_key_test(){
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];



        let mut context = AESContext::new(AesMode::ECB, AesSize::S128, None);
        context.set_key(key.as_slice());
        context.print_round_keys(&key);
    }
}
