package me.totoku103.crypto.kisa.sha2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class Sha256Test {

    @Test
    public void test() {
        final String message = "message";
        final String encrypt = Sha256.encrypt(message.getBytes());

        final byte[] pbCipher = new byte[32];
        Sha256.encrypt(message.getBytes(), message.length(), pbCipher);
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 32; i++)
            sb.append(Integer.toHexString(0xff & pbCipher[i]));

        Assertions.assertEquals(encrypt, sb.toString());
        System.out.println(encrypt);
    }
}