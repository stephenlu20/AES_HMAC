package com.crypto;

import java.util.Arrays;

// Simple flow for encrypting something and then "sending" it to someone
// AES is a symmetric cipher, so the sender and reciever should both know the key
// same for HMAC, both people need to know the key
// the sender first encrypts using AES with the key and then hashes the resulting cipher text with HMAC
// the sender sends both the hash and the cipher text
// the reciever will then hash the recieved cipher text with HMAC
// and compare with recieved hash with their own computed one
// if there are no differences, the cipher was not tampered with in transit
// then the receiever can decrypt using the key

public class App 
{
    public static void main(String[] args) {
        // AES key
        byte[] aesKey = new byte[] {
            (byte)0x2B, (byte)0x7E, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xAE, (byte)0xD2, (byte)0xA6,
            (byte)0xAB, (byte)0xF7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xCF, (byte)0x4F, (byte)0x3C
        };

        // plaintext
        byte[] plaintext = new byte[] {
            (byte)0x6B, (byte)0xC1, (byte)0xBE, (byte)0xE2,
            (byte)0x2E, (byte)0x40, (byte)0x9F, (byte)0x96,
            (byte)0xE9, (byte)0x3D, (byte)0x7E, (byte)0x11,
            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2A
        };

        // HMAC key
        byte[] hmacKey = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
        };

        // AES and HMAC
        AES aes = new AES(aesKey);
        HMAC hmac = new HMAC(hmacKey);

        System.out.println("Input: " + bytesToHex(plaintext));

        // Encrypt the plaintext block
        byte[] ciphertext = aes.encryptBlock(plaintext);
        System.out.println("Encrypted: " + bytesToHex(ciphertext));

        // Compute HMAC of the ciphertext
        byte[] hash = hmac.compute(ciphertext);
        System.out.println("HMAC hash: " + bytesToHex(hash));

        System.out.println("Pretending the cipher text and the HMAC hash was \"sent\" to someone");

        // Compute and compare hashes
        byte[] verifyHMAC = hmac.compute(ciphertext);

        System.out.println("Does the recived hash equal the computed hash from the cipher?");
        System.out.println(Arrays.equals(verifyHMAC, hash));
        System.out.println("If true, the ciphertext was not tampered");

        byte[] decryptedCipher = aes.decryptBlock(ciphertext);
        System.out.println("Check if the decrypted text matches");
        System.out.println(Arrays.equals(decryptedCipher, plaintext));
        System.out.println("If true, the cipher encrypts and decrypts correctly.");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
