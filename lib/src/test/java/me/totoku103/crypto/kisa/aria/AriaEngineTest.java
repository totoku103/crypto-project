package me.totoku103.crypto.kisa.aria;

import me.totoku103.crypto.kisa.aria.Aria;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class AriaEngineTest {
    // 16진수 문자열을 바이트 배열로 변환
    private static byte[] fromHex(final String hex) {
        final int len = hex.length();
        final byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    @Test
    @DisplayName("새 구현과 기존 구현 비교")
    public void testEngineMatchesOriginal() throws InvalidKeyException {
        final byte[] key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        final byte[] plain = fromHex("00112233445566778899aabbccddeeff");

        final Aria original = new Aria(256);
        original.setKey(key);
        original.setupRoundKeys();
        final byte[] expected = original.encrypt(plain, 0);

        final Aria engine = new Aria(256);
        engine.setKey(key);
        engine.setupRoundKeys();
        final byte[] actual = engine.encrypt(plain, 0);

        assertArrayEquals(expected, actual);
        assertArrayEquals(plain, engine.decrypt(actual, 0));
    }
}
