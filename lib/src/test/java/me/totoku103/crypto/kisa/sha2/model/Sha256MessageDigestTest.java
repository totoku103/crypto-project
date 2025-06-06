package me.totoku103.crypto.kisa.sha2.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;

class Sha256MessageDigestTest {

    @Test
    void compareWithJdk() throws Exception {
        String message = "message";
        Sha256MessageDigest md = new Sha256MessageDigest();
        byte[] result = md.toHash(message.getBytes());

        MessageDigest jdk = MessageDigest.getInstance("SHA-256");
        byte[] expected = jdk.digest(message.getBytes());
        Assertions.assertArrayEquals(expected, result);
    }

    @Test
    void hexStringWithPadding() throws Exception {
        String message = "message";
        Sha256MessageDigest md = new Sha256MessageDigest();
        String hex = md.encrypt(message.getBytes());

        MessageDigest jdk = MessageDigest.getInstance("SHA-256");
        StringBuilder sb = new StringBuilder();
        for (byte b : jdk.digest(message.getBytes())) {
            sb.append(String.format("%02x", b & 0xff));
        }
        Assertions.assertEquals(sb.toString(), hex);
    }

    @Test
    void compareWithVanilla() {
        String message = "message";
        Sha256MessageDigest md = new Sha256MessageDigest();
        byte[] result = md.toHash(message.getBytes());

        byte[] vanilla = new byte[32];
        Sha256Vanilla.encrypt(message.getBytes(), message.length(), vanilla);
        Assertions.assertArrayEquals(vanilla, result);
    }

    @Test
    void compareOnlineEncryptValue() {
        final String message = "message";
        final String onlineEncrypt = "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d";
        final Sha256MessageDigest md = new Sha256MessageDigest();
        final String encrypt = md.encrypt(message.getBytes());
        Assertions.assertEquals(onlineEncrypt, encrypt);
    }
}
