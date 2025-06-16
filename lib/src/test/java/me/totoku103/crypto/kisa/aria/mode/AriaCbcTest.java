package me.totoku103.crypto.kisa.aria.mode;


import me.totoku103.crypto.kisa.aria.Aria;
import me.totoku103.crypto.utils.ConvertUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.InvalidKeyException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class AriaCbcTest {
    private static final byte[] IV = ConvertUtils.fromHex("0f1e2d3c4b5a69788796a5b4c3d2e1f0");

    private static Stream<Arguments> cbcTestVectors() {
        return Stream.of(
                Arguments.of(
                        128,
                        "00112233445566778899aabbccddeeff",
                        "11111111aaaaaaaa11111111bbbbbbbb",
                        "18eec44c6d8318b2e72677dbeb58ff76"
                ),
                Arguments.of(
                        192,
                        "00112233445566778899aabbccddeeff0011223344556677",
                        "11111111aaaaaaaa11111111bbbbbbbb",
                        "b36554307dba72b1c8edc1854e34d3a2"
                ),
                Arguments.of(
                        256,
                        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                        "11111111aaaaaaaa11111111bbbbbbbb",
                        "f1d5a826a11b230ad6df7a1701fa9f3c"
                )
        );
    }

    @ParameterizedTest(name = "[{index}] {0}-bit key – CBC mode with fixed IV")
    @MethodSource("cbcTestVectors")
    @DisplayName("ARIA CBC mode encryption/decryption with fixed IV")
    void testCbcWithFixedIv(int keySize, String keyHex, String ptHex, String ctHex) throws InvalidKeyException {

    }
}
