package me.totoku103.crypto.java.sha3;

import me.totoku103.crypto.enums.Sha3AlgorithmType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class Sha3Test {
    // 바이트 배열을 16진수 문자열로 변환
    private static String toHex(final byte[] data) {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Test
    @DisplayName("BitSizeType별 MessageDigest 인스턴스 생성 가능 여부 검증")
    public void testMessageDigestInstanceCreationByBitSizeType() {
        Assumptions.assumeTrue(Sha3.isSha3Available(Sha3AlgorithmType.SHA3_224));
        Arrays.asList(Sha3AlgorithmType.values())
                .forEach(type -> {
                    final MessageDigest instance;
                    try {
                        instance = MessageDigest.getInstance(type.getAlgorithmName());
                        Assertions.assertNotNull(instance);
                    } catch (NoSuchAlgorithmException e) {
                        Assertions.fail("Failed to create MessageDigest instance for " + type.getAlgorithmName(), e);
                    }
                });
    }

    @Test
    @DisplayName("한글 입력 SHA3-512(최적화, 지원 시 실행)")
    public void testOptimizedKorean512() {
        me.totoku103.crypto.java.sha3.Sha3.isSha3Available(Sha3AlgorithmType.SHA3_512);
        final me.totoku103.crypto.java.sha3.Sha3 optimized = new me.totoku103.crypto.java.sha3.Sha3();
        final byte[] input = "테스트".getBytes(StandardCharsets.UTF_8);
        final byte[] digest = optimized.toHash(input, Sha3AlgorithmType.SHA3_512);
        assertEquals(
                "1202c701bda679497bd9fae351efb4bc96656a4ba78b184711645515ce7aa410279865413bb67a8df2257ed866aa5f8688cc46a2f19e3ac9420197692b4fde18",
                toHex(digest));
    }

    @Test
    @DisplayName("이모지 입력 비교 (최적화 지원 시 실행)")
    public void testUnicodeOptimizedMatchesOriginal() {
        me.totoku103.crypto.java.sha3.Sha3.isSha3Available(Sha3AlgorithmType.SHA3_256);
        final me.totoku103.crypto.kisa.sha3.Sha3 original = new me.totoku103.crypto.kisa.sha3.Sha3();
        final me.totoku103.crypto.java.sha3.Sha3 optimized = new me.totoku103.crypto.java.sha3.Sha3();
        final byte[] input = "emoji \uD83D\uDE00".getBytes(StandardCharsets.UTF_8);
        final byte[] expected = new byte[32];
        final int rc = original.toHash(expected, expected.length, input, input.length, 256, 0);
        assertEquals(0, rc);
        final byte[] actual = optimized.toHash(input, Sha3AlgorithmType.SHA3_256);
        assertArrayEquals(expected, actual);
        assertEquals("72a5ac0c9cbab2f48b1fc74e951d1102da6de1990c42d1610bfa2cee29e4f86f", toHex(actual));
    }

    @Test
    @DisplayName("모든 비트 크기 일치 테스트 (최적화 지원 시 실행)")
    public void testAllBitSizesMatch() {
        me.totoku103.crypto.java.sha3.Sha3.isSha3Available(Sha3AlgorithmType.SHA3_256);
        final me.totoku103.crypto.kisa.sha3.Sha3 original = new me.totoku103.crypto.kisa.sha3.Sha3();
        final me.totoku103.crypto.java.sha3.Sha3 optimized = new me.totoku103.crypto.java.sha3.Sha3();
        final byte[] input = "OpenAI".getBytes(StandardCharsets.UTF_8);
        Arrays.stream(Sha3AlgorithmType.values())
                .forEach(bitType -> {
                    final int bit = bitType.getBitSize();
                    final byte[] expected = new byte[bit / 8];
                    final int rc = original.toHash(expected, expected.length, input, input.length, bit, 0);
                    assertEquals(0, rc);
                    final byte[] actual = optimized.toHash(input, bitType);
                    assertArrayEquals(expected, actual, "bitSize=" + bit);
                });
    }

    @Test
    @DisplayName("최적화 버전 결과 비교 (SHA3-256 지원 시에만 실행)")
    public void testOptimizedMatchesOriginal() throws Exception {
        me.totoku103.crypto.java.sha3.Sha3.isSha3Available(Sha3AlgorithmType.SHA3_256);
        final me.totoku103.crypto.kisa.sha3.Sha3 original = new me.totoku103.crypto.kisa.sha3.Sha3();
        final me.totoku103.crypto.java.sha3.Sha3 optimized = new me.totoku103.crypto.java.sha3.Sha3();
        final byte[] input = "hello world".getBytes(StandardCharsets.UTF_8);

        final byte[] expected = new byte[32];
        final int rc = original.toHash(expected, expected.length, input, input.length, 256, 0);
        assertEquals(0, rc);

        final byte[] actual = optimized.toHash(input, Sha3AlgorithmType.SHA3_256);
        assertArrayEquals(expected, actual);
    }

}