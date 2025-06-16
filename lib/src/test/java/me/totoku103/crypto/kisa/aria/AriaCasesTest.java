package me.totoku103.crypto.kisa.aria;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AriaCasesTest {

    @Test
    @DisplayName("여러 키 길이에 대한 암복호 라운드트립")
    void testRoundTrip() throws InvalidKeyException {
        final String[][] vectors = {
                {"128", "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff"},
                {"192", "000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff"},
                {"256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff"}
        };

        for (String[] v : vectors) {
            final int keySize = Integer.parseInt(v[0]);
            final byte[] key = Aria.fromHex(v[1]);
            final byte[] plain = Aria.fromHex(v[2]);

            final Aria aria = new Aria(keySize);
            aria.setKey(key);
            aria.setupRoundKeys();

            final byte[] enc = aria.encrypt(plain, 0);
            final byte[] dec = aria.decrypt(enc, 0);
            assertArrayEquals(plain, dec);
        }
    }

    @Test
    @DisplayName("잘못된 키 사이즈 예외 확인")
    void testInvalidKeySize() {
        assertThrows(InvalidKeyException.class, () -> new Aria(100));
    }

    @Test
    @DisplayName("키 설정 없이 암호화 시 예외")
    void testEncryptWithoutKey() throws InvalidKeyException {
        final Aria aria = new Aria(128);
        final byte[] plain = new byte[16];
        final byte[] out = new byte[16];
        assertThrows(InvalidKeyException.class, () -> aria.encrypt(plain, 0, out, 0));
    }

    @Test
    @DisplayName("짧은 키 입력시 예외")
    void testShortKey() throws InvalidKeyException {
        final Aria aria = new Aria(256);
        final byte[] shortKey = new byte[16];
        assertThrows(InvalidKeyException.class, () -> aria.setKey(shortKey));
    }

    @Test
    @DisplayName("reset 후 재사용 확인")
    void testReuseAfterReset() throws InvalidKeyException {
        final Aria aria = new Aria(128);
        final byte[] key1 = Aria.fromHex("000102030405060708090a0b0c0d0e0f");
        final byte[] plain = Aria.fromHex("00112233445566778899aabbccddeeff");
        aria.setKey(key1);
        aria.setupRoundKeys();
        final byte[] enc1 = aria.encrypt(plain, 0);
        assertArrayEquals(plain, aria.decrypt(enc1, 0));

        aria.reset();
        aria.setKeySize(192);
        final byte[] key2 = Aria.fromHex("000102030405060708090a0b0c0d0e0f1011121314151617");
        aria.setKey(key2);
        aria.setupRoundKeys();
        final byte[] enc2 = aria.encrypt(plain, 0);
        assertArrayEquals(plain, aria.decrypt(enc2, 0));
    }
}

