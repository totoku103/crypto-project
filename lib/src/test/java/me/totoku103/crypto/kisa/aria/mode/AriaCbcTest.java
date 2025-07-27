package me.totoku103.crypto.kisa.aria.mode;

import me.totoku103.crypto.core.utils.ByteUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.InvalidKeyException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class AriaCbcTest {
    private static final byte[] IV = ByteUtils.fromHexString("0f1e2d3c4b5a69788796a5b4c3d2e1f0");

    private static Stream<Arguments> cbcTestVectors() {
        return Stream.of(
                Arguments.of(
                        128,
                        "00112233445566778899aabbccddeeff",
                        "11111111aaaaaaaa11111111bbbbbbbb",
                        "49d61860b14909109cef0d22a9268134"),
                Arguments.of(
                        192,
                        "00112233445566778899aabbccddeeff0011223344556677",
                        "11111111aaaaaaaa11111111bbbbbbbb",
                        "afe6cf23974b533c672a826264ea785f"),
                Arguments.of(
                        256,
                        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                        "11111111aaaaaaaa11111111bbbbbbbb",
                        "523a8a806ae621f155fdd28dbc34e1ab"));
    }

    @ParameterizedTest(name = "[{index}] {0}-bit key – CBC mode with fixed IV")
    @MethodSource("cbcTestVectors")
    @DisplayName("고정된 IV를 사용한 CBC 모드 암복호화가 테스트 벡터와 일치하는지 확인")
    void cbcWithFixedIvShouldMatchVectors(int keySize, String keyHex, String ptHex, String ctHex) {
        byte[] key = ByteUtils.fromHexString(keyHex);
        byte[] plain = ByteUtils.fromHexString(ptHex);
        byte[] expected = ByteUtils.fromHexString(ctHex);

        byte[] cipher = AriaModes.encryptCbc(key, IV, plain);
        assertArrayEquals(expected, cipher);

        byte[] dec = AriaModes.decryptCbc(key, IV, cipher);
        assertArrayEquals(plain, dec);
    }
}
