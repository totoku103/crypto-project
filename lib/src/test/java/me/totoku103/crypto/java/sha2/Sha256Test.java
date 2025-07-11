package me.totoku103.crypto.java.sha2;

import me.totoku103.crypto.utils.HexConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class Sha256Test {

    private Sha256 sha256;

    @BeforeEach
    void setUp() {
        this.sha256 = new Sha256();
    }

    @Test
    @DisplayName("JDK에서 SHA-256 알고리즘을 지원하는지 확인")
    void isSha256Available() {
        assertTrue(Sha256.isSha256Available(), "SHA-256 should be available in a standard JDK environment");
    }

    @Test
    @DisplayName("encrypt(): 빈 문자열 해싱 테스트")
    void encrypt_emptyString() {
        final String plainText = "";
        final byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        final String expectedHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        final String actualHex = sha256.encrypt(plainBytes);

        assertEquals(expectedHex, actualHex);
    }

    @Test
    @DisplayName("encrypt(): 'abc' 문자열 해싱 테스트")
    void encrypt_abcString() {
        final String plainText = "abc";
        final byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        final String expectedHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        final String actualHex = sha256.encrypt(plainBytes);

        assertEquals(expectedHex, actualHex);
    }

    @Test
    @DisplayName("toHash(): 'abc' 문자열 해싱 결과 바이트 배열 테스트")
    void toHash_abcString() {
        final String plainText = "abc";
        final byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        final byte[] expectedHash = HexConverter.toBytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        final byte[] actualHash = sha256.toHash(plainBytes);

        assertArrayEquals(expectedHash, actualHash);
    }

    @Test
    @DisplayName("sha256Hash(): 'abc' 문자열 해싱 결과를 제공된 버퍼에 저장")
    void sha256Hash_abcString() {
        final String plainText = "abc";
        final byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        final byte[] expectedHash = HexConverter.toBytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        final byte[] outputBuffer = new byte[32];

        final int result = sha256.sha256Hash(outputBuffer, outputBuffer.length, plainBytes, plainBytes.length);

        assertEquals(0, result, "Hashing should be successful");
        assertArrayEquals(expectedHash, outputBuffer);
    }

    @Test
    @DisplayName("sha256Hash(): 출력 버퍼 크기가 다를 경우 에러 반환")
    void sha256Hash_invalidOutputLength() {
        final byte[] plainBytes = "test".getBytes(StandardCharsets.UTF_8);
        final byte[] outputBuffer = new byte[31]; // Invalid length

        final int result = sha256.sha256Hash(outputBuffer, outputBuffer.length, plainBytes, plainBytes.length);

        assertEquals(1, result, "Should return parameter error for incorrect output buffer size");
    }
}
