package me.totoku103.crypto.kisa.sha2;

import me.totoku103.crypto.utils.HexConverter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class Sha256Test {

    @Test
    @DisplayName("encrypt(byte[], int, byte[]): 'abc' 문자열 해싱 테스트")
    void encrypt_byteArrayOutput() {
        final String plainText = "abc";
        final byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        final byte[] expectedHash = HexConverter.toBytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        final byte[] actualHash = new byte[32];

        Sha256.encrypt(plainBytes, plainBytes.length, actualHash);

        assertArrayEquals(expectedHash, actualHash);
    }

    @Test
    @DisplayName("encrypt(byte[]): 'abc' 문자열 해싱 결과 문자열 테스트 (KISA 방식)")
    void encrypt_stringOutput_abc() {
        final String plainText = "abc";
        final byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        // KISA 구현은 16진수 변환 시 패딩을 하지 않으므로(e.g., 0x01 -> "1"), 예상 결과가 다름
        final String expectedString = "ba7816bf8f1cfea414140de5dae2223b0361a396177a9cb410ff61f2015ad";

        final String actualString = Sha256.encrypt(plainBytes);

        assertEquals(expectedString, actualString);
    }

    @Test
    @DisplayName("encrypt(byte[]): 빈 문자열 해싱 결과 문자열 테스트 (KISA 방식)")
    void encrypt_stringOutput_empty() {
        final String plainText = "";
        final byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // KISA 방식(패딩 없음): e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // 이 경우, 0x10 미만의 바이트가 없으므로 표준 16진수 문자열과 결과가 동일
        final String expectedString = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        final String actualString = Sha256.encrypt(plainBytes);

        assertEquals(expectedString, actualString);
    }
}
