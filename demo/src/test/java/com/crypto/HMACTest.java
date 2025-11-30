package com.crypto;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.junit.Test;

public class HMACTest {

    @Test
    public void testHMAC() {
        byte[] key = new byte[20];
        Arrays.fill(key, (byte)0x0B);

        HMAC hmac = new HMAC(key);
        byte[] result = hmac.compute("Hi There".getBytes());

        String expected = "B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7".toLowerCase();

        assertEquals(expected, bytesToHex(result).toLowerCase());
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
