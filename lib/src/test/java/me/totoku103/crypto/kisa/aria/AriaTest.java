package me.totoku103.crypto.kisa.aria;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AriaTest {
    // 16진수 문자열을 바이트 배열로 변환
    private static byte[] fromHex(final String hex) {
        final int len = hex.length();
        final byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    // 바이트 배열을 16진수 문자열로 변환
    private static String toHex(final byte[] data) {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Test
    @DisplayName("RFC5794 공식 벡터 검증")
    public void testOfficialVectors() throws InvalidKeyException {
        final String[][] vectors = {
                {
                        "128",
                        "000102030405060708090a0b0c0d0e0f",
                        "00112233445566778899aabbccddeeff",
                        "d718fbd6ab644c739da95f3be6451778"
                },
                {
                        "192",
                        "000102030405060708090a0b0c0d0e0f1011121314151617",
                        "00112233445566778899aabbccddeeff",
                        "26449c1805dbe7aa25a468ce263a9e79"
                },
                {
                        "256",
                        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                        "00112233445566778899aabbccddeeff",
                        "f92bd7c79fb72e2f2b8f80c1972d24fc"
                }
        };

        for (String[] v : vectors) {
            final int keySize = Integer.parseInt(v[0]);
            final byte[] key = fromHex(v[1]);
            final byte[] plain = fromHex(v[2]);
            final byte[] expected = fromHex(v[3]);

            final Aria aria = new Aria(keySize);
            aria.setKey(key);
            aria.setupRoundKeys();
            final byte[] enc = aria.encrypt(plain, 0);
            assertEquals(toHex(expected), toHex(enc));

            final byte[] dec = aria.decrypt(enc, 0);
            assertArrayEquals(plain, dec);
        }
    }
}
