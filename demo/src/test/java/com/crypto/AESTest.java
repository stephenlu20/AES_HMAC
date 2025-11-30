package com.crypto;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class AESTest {

    @Test
    public void testEncryptBlockAES128() {
        // Key
        byte[] key = new byte[] {
            (byte)0x2B, (byte)0x7E, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xAE, (byte)0xD2, (byte)0xA6,
            (byte)0xAB, (byte)0xF7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xCF, (byte)0x4F, (byte)0x3C
        };

        // Plaintext block
        byte[] plaintext = new byte[] {
            (byte)0x6B, (byte)0xC1, (byte)0xBE, (byte)0xE2,
            (byte)0x2E, (byte)0x40, (byte)0x9F, (byte)0x96,
            (byte)0xE9, (byte)0x3D, (byte)0x7E, (byte)0x11,
            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2A,
        };

        // Expected ciphertext from NIST test vector
        String expectedHex = "3AD77BB40D7A3660A89ECAF32466EF97";

        AES aes = new AES(key);
        byte[] cipher = aes.encryptBlock(plaintext);

        String actualHex = bytesToHex(cipher);

        assertEquals(expectedHex.toLowerCase(), actualHex.toLowerCase());
    }

    @Test
    public void testEncryptBlocksAES128() {
        // Key
        byte[] key = new byte[] {
            (byte)0x2B, (byte)0x7E, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xAE, (byte)0xD2, (byte)0xA6,
            (byte)0xAB, (byte)0xF7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xCF, (byte)0x4F, (byte)0x3C
        };

        // Plaintext block
        byte[] plaintext = new byte[] {
            (byte)0x6B, (byte)0xC1, (byte)0xBE, (byte)0xE2,
            (byte)0x2E, (byte)0x40, (byte)0x9F, (byte)0x96,
            (byte)0xE9, (byte)0x3D, (byte)0x7E, (byte)0x11,
            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2A,
            
            (byte)0xAE, (byte)0x2D, (byte)0x8A, (byte)0x57,
            (byte)0x1E, (byte)0x03, (byte)0xAC, (byte)0x9C,
            (byte)0x9E, (byte)0xB7, (byte)0x6F, (byte)0xAC,
            (byte)0x45, (byte)0xAF, (byte)0x8E, (byte)0x51,
            
            (byte)0x30, (byte)0xC8, (byte)0x1C, (byte)0x46,
            (byte)0xA3, (byte)0x5C, (byte)0xE4, (byte)0x11,
            (byte)0xE5, (byte)0xFB, (byte)0xC1, (byte)0x19,
            (byte)0x1A, (byte)0x0A, (byte)0x52, (byte)0xEF,
            
            (byte)0xF6, (byte)0x9F, (byte)0x24, (byte)0x45,
            (byte)0xDF, (byte)0x4F, (byte)0x9B, (byte)0x17,
            (byte)0xAD, (byte)0x2B, (byte)0x41, (byte)0x7B,
            (byte)0xE6, (byte)0x6C, (byte)0x37, (byte)0x10
        };

        // Expected ciphertext from NIST test vector
        String expectedHex = "3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4";

        AES aes = new AES(key);
        byte[] cipher = aes.encryptBlocks(plaintext);

        String actualHex = bytesToHex(cipher);

        // Assert equality
        assertEquals(expectedHex.toLowerCase(), actualHex.toLowerCase());
    }
    
    @Test
    public void testDecryptBlockAES128() {
        // Key
        byte[] key = new byte[] {
            (byte)0x2B, (byte)0x7E, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xAE, (byte)0xD2, (byte)0xA6,
            (byte)0xAB, (byte)0xF7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xCF, (byte)0x4F, (byte)0x3C
        };

        // Plaintext block
        byte[] ciphertext = new byte[] {
            (byte)0x3A, (byte)0xD7, (byte)0x7B, (byte)0xB4,
            (byte)0x0D, (byte)0x7A, (byte)0x36, (byte)0x60,
            (byte)0xA8, (byte)0x9E, (byte)0xCA, (byte)0xF3,
            (byte)0x24, (byte)0x66, (byte)0xEF, (byte)0x97
        };

        // Expected ciphertext after decryption
        String expectedHex = "6BC1BEE22E409F96E93D7E117393172A";

        AES aes = new AES(key);
        byte[] decrypted = aes.decryptBlock(ciphertext);

        String actualHex = bytesToHex(decrypted);

        assertEquals(expectedHex.toLowerCase(), actualHex.toLowerCase());
    }

    @Test
    public void testDecryptBlocksAES128() {
        // Key
        byte[] key = new byte[] {
            (byte)0x2B, (byte)0x7E, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xAE, (byte)0xD2, (byte)0xA6,
            (byte)0xAB, (byte)0xF7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xCF, (byte)0x4F, (byte)0x3C
        };

        // Ciphertext blocks from NIST AES-128 test vector
        byte[] ciphertext = new byte[] {
            (byte)0x3A, (byte)0xD7, (byte)0x7B, (byte)0xB4,
            (byte)0x0D, (byte)0x7A, (byte)0x36, (byte)0x60,
            (byte)0xA8, (byte)0x9E, (byte)0xCA, (byte)0xF3,
            (byte)0x24, (byte)0x66, (byte)0xEF, (byte)0x97,

            (byte)0xF5, (byte)0xD3, (byte)0xD5, (byte)0x85,
            (byte)0x03, (byte)0xB9, (byte)0x69, (byte)0x9D,
            (byte)0xE7, (byte)0x85, (byte)0x89, (byte)0x5A,
            (byte)0x96, (byte)0xFD, (byte)0xBA, (byte)0xAF,

            (byte)0x43, (byte)0xB1, (byte)0xCD, (byte)0x7F,
            (byte)0x59, (byte)0x8E, (byte)0xCE, (byte)0x23,
            (byte)0x88, (byte)0x1B, (byte)0x00, (byte)0xE3,
            (byte)0xED, (byte)0x03, (byte)0x06, (byte)0x88,

            (byte)0x7B, (byte)0x0C, (byte)0x78, (byte)0x5E,
            (byte)0x27, (byte)0xE8, (byte)0xAD, (byte)0x3F,
            (byte)0x82, (byte)0x23, (byte)0x20, (byte)0x71,
            (byte)0x04, (byte)0x72, (byte)0x5D, (byte)0xD4
        };

        // Expected plaintext blocks
        String expectedHex = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";

        AES aes = new AES(key);
        byte[] decrypted = aes.decryptBlocks(ciphertext);

        String actualHex = bytesToHex(decrypted);

        assertEquals(expectedHex.toLowerCase(), actualHex.toLowerCase());
    }

    // Helper method for converting bytes to hex
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
