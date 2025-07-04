package me.totoku103.crypto.kisa.sha2;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Sha512Test {
    private static String toHex(final byte[] data) {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Test
    @DisplayName("공식 테스트 벡터 SHA512(abc) 검증")
    public void shouldMatchSha512Vector() {
        final byte[] input = "abc".getBytes(StandardCharsets.UTF_8);
        final byte[] out = Sha512.toHash(input);
        assertEquals(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                toHex(out));
    }

    @Test
    @DisplayName("한글 문자열 SHA512 해시 확인")
    public void shouldHashKoreanText() {
        final byte[] input = "테스트".getBytes(StandardCharsets.UTF_8);
        final byte[] out = Sha512.toHash(input);
        assertEquals(
                "075789001ce21770acbc8cd62fc1893e15a00cbc25640e08f51c5c85116dc5b1be72af82d543c3675a2e66a21c7f954feb54c3d25e6b24afe0dba42b2f563914",
                toHex(out));
    }
}
