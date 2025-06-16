package me.totoku103.crypto.kisa.aria;

import me.totoku103.crypto.utils.ConvertUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.InvalidKeyException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AriaTest {

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
            final byte[] key = ConvertUtils.fromHex(v[1]);
            final byte[] plain = ConvertUtils.fromHex(v[2]);
            final byte[] expected = ConvertUtils.fromHex(v[3]);

            final Aria aria = new Aria(keySize);
            aria.setKey(key);
            aria.setupRoundKeys();
            final byte[] enc = aria.encrypt(plain, 0);
            assertEquals(ConvertUtils.toHex(expected), ConvertUtils.toHex(enc));

            final byte[] dec = aria.decrypt(enc, 0);
            assertArrayEquals(plain, dec);
        }
    }

    /**
     * Official ARIA ECB test vectors (key, plaintext, ciphertext).
     * Source: “ARIA test vectors” (KISA).
     */
    private static Stream<Arguments> testVectors() {
        return Stream.of(
                // 128‑bit key
                Arguments.of(
                        128,
                        "00112233445566778899aabbccddeeff",
                        "11111111aaaaaaaa11111111bbbbbbbb",
                        "c6ecd08e22c30abdb215cf74e2075e6e"
                ),
                // 192‑bit key
                Arguments.of(
                        192,
                        "00112233445566778899aabbccddeeff0011223344556677",
                        "11111111aaaaaaaa11111111bbbbbbbb",
                        "8d1470625f59ebacb0e55b534b3e462b"
                ),
                // 256‑bit key
                Arguments.of(
                        256,
                        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                        "11111111aaaaaaaa11111111bbbbbbbb",
                        "58a875e6044ad7fffa4f58420f7f442d"
                )
        );
    }

    @ParameterizedTest(name = "[{index}] {0}-bit key – ECB round‑trip")
    @MethodSource("testVectors")
    @DisplayName("ARIA official ECB test vectors encrypt/decrypt round‑trip")
    void ecbVectorsShouldMatchSpec(int keySize, String keyHex, String ptHex, String ctHex) throws InvalidKeyException {
        Aria aria = new Aria(keySize);
        aria.setKey(ConvertUtils.fromHex(keyHex));

        byte[] plaintext = ConvertUtils.fromHex(ptHex);
        byte[] expectedCipher = ConvertUtils.fromHex(ctHex);

        byte[] actualCipher = aria.encrypt(plaintext, 0);
        assertArrayEquals(expectedCipher, actualCipher, "Ciphertext does not match specification");

        byte[] roundTripPlain = aria.decrypt(actualCipher, 0);
        assertArrayEquals(plaintext, roundTripPlain, "Decryption failed to recover original plaintext");
    }
}
