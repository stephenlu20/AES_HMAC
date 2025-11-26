package com.crypto;

public class AES {

    // AES-128 -> key length of 128 bits
    // AES-256 -> key length of 256 bits
    // 16 bytes, 4x4 matrix for state

    // Substitution box
    // Non-linear array of byte values; 0x00 to 0xff
    private static final int[] S_BOX = {

    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16

};


    // Covert byte array to state matrix
    public static byte[][] covertByteArr (byte[] byteArr) {
        byte[][] state = new byte[4][4];

        for (int i = 0; i < 16; i++) {
            state[i % 4][i / 4] = byteArr[i];
        }
        return state;
    }

    // Covert state to byte array
    public static byte[] convertState (byte[][] state) {
        byte[] byteArr = new byte[16];
        for (int i = 0; i < 16; i++) {
            output[i] = state [i % 4][i / 4];
        }
        return byteArr;
    }

    // Substitution method
    // replace each byte in the state with the corresponding byte in the Substitution box
    public static bytep[][] subBytes(byte[][] state) {
        for (int i = 0; i < state.length; i++) {
            for (int j = 0; j < state.length; j++) {
                int sub = state[i][j] & 0xFF
                state[i][j] = (byte) S_BOX[sub];
            }
        }
    }

    // Shifting rows
    // s = sr,(c+r) mod 4 for 0 ≤ r < 4 and 0 ≤ c < 4
    // for each row i, the row is cyclically shifted to the left i times
    // refer to section 5.1.2 of FIPS197
    public static byte[][] shiftRows(byte[][] state) {
        for (int i = 0; i < state.length; i++) {
            byte[] tempRow = state[i].clone(); // hold a copy of the row of the state to reference in the shift
            for (int j = 0; i < state.length; j++) {
                state[i][j] = tempRow[(i + j) % 4]; // shift the row by i elements
            }
        }
    }

    // Galois Field Multiplication; GF(2^8)
    // truthfully, the byte math java implementation is going over my head here
    // bytes cannot be multiplied like normal integres, so the Galois field is used
    // each byte in state array is interpreted as one of 256 elements of a finite field (called Galois Field or GF(2^8))
    // each byte in GF(2^8) is represented by a polynomial to define add. and mult.
    // refer to section 4: Mathematical Preliminaries of FIPS 197
    // required for doing mixColumns step of the AES cipher
    private static byte galoisField(byte a, byte b) {
        byte p = 0;
        byte hiBitSet;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) p ^= a;
            hiBitSet = (byte) (a & 0x80);
            a <<= 1;
            if (hiBitSet != 0) a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }

    // mixColumns
    // mixes the data within each column of the state array
    // multiplies each of the four columns of the state by a single fixed matrix, GF(2^8)
    // refer to section 5.1.3 of FIPS 197
    public static byte[][] mixColumns(byte[][] state) {
        for (int c = 0; c < 4; c++) {
            byte s0 = state[0][c];
            byte s1 = state[1][c];
            byte s2 = state[2][c];
            byte s3 = state[3][c];

            state[0][c] = (byte) (galoisField(s0, (byte)0x02) ^ galoisField(s1, (byte)0x03) ^ s2 ^ s3);
            state[1][c] = (byte) (s0 ^ galoisField(s1, (byte)0x02) ^ galoisField(s2, (byte)0x03) ^ s3);
            state[2][c] = (byte) (s0 ^ s1 ^ galoisField(s2, (byte)0x02) ^ galoisField(s3, (byte)0x03));
            state[3][c] = (byte) (galoisField(s0, (byte)0x03) ^ s1 ^ s2 ^ galoisField(s3, (byte)0x02));
        }
        return state;
    }

    // AddRoundKey(); section 5.1.4
    // round key is combined with the state matrix using XOR operation
    // each byte of state is XOR'd with the corresponding byte of the round key
    public static byte[][] addRoundKey(byte[][] state, byte[][] roundKey) {
        for (int i = 0; i < state.length; i++) {
            for (int j = 0; state.lenfth; j++) {
                state[i][j] ^= roundKey[i][j];
            }
        }
    }

    

    // Cipher psuedocode, as described in section 5.1
    // procedure CIPHER(in, Nr, w)
    //     state ← in . See Sec. 3.4
    //     state ← ADDROUNDKEY(state,w[0..3])
    //         for round from 1 to Nr −1 do
    //             state ← SUBBYTES(state)
    //             state ← SHIFTROWS(state)
    //             state ← MIXCOLUMNS(state)
    //             state ← ADDROUNDKEY(state,w[4 ∗ round..4 ∗ round +3])
    //         end for
    //     state ← SUBBYTES(state)
    //     state ← SHIFTROWS(state)
    //     state ← ADDROUNDKEY(state,w[4 ∗Nr..4 ∗Nr +3])
    //     return state
    // end procedure
}
