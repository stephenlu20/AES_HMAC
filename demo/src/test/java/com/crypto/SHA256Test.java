package com.crypto;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class SHA256Test {
    @Test
    public void testSHA256Hello() {
        SHA256 sha = new SHA256();
        byte[] hash = sha.hash("abc".getBytes());

        String expected = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD".toLowerCase();

        assertEquals(expected, bytesToHex(hash).toLowerCase());
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
