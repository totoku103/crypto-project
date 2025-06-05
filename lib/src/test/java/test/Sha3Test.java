package test;

import me.totoku103.crypto.kisa.sha3.sha3;
import me.totoku103.crypto.kisa.sha3.Sha3Optimized;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

// SHA-3 단위 테스트
public class Sha3Test {

    // 바이트 배열을 16진수 문자열로 변환
    private static String toHex(final byte[] data) {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // SHA3 지원 여부 확인
    private static boolean isSha3Available(final int bitSize) {
        try {
            java.security.MessageDigest.getInstance("SHA3-" + bitSize);
            return true;
        } catch (java.security.NoSuchAlgorithmException e) {
            return false;
        }
    }

    // SHA3-256 벡터 테스트
    @Test
    public void testSha3256Vector() {
        final sha3 hasher = new sha3();
        final byte[] input = "abc".getBytes(StandardCharsets.UTF_8);
        final byte[] out = new byte[32];
        final int rc = hasher.sha3Hash(out, out.length, input, input.length, 256, 0);
        assertEquals(0, rc);
        assertEquals("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", toHex(out));
    }

    // 최적화 버전 결과 비교 (SHA3-256 지원 시에만 실행)
    @Test
    public void testOptimizedMatchesOriginal() throws Exception {
        Assumptions.assumeTrue(isSha3Available(256));
        final sha3 original = new sha3();
        final Sha3Optimized optimized = new Sha3Optimized();
        final byte[] input = "hello world".getBytes(StandardCharsets.UTF_8);

        final byte[] expected = new byte[32];
        final int rc = original.sha3Hash(expected, expected.length, input, input.length, 256, 0);
        assertEquals(0, rc);

        final byte[] actual = optimized.digest(input, 256);
        assertArrayEquals(expected, actual);
    }

    // 한글 입력 SHA3-256
    @Test
    public void testKoreanVector256() {
        final sha3 hasher = new sha3();
        final byte[] input = "안녕하세요".getBytes(StandardCharsets.UTF_8);
        final byte[] out = new byte[32];
        final int rc = hasher.sha3Hash(out, out.length, input, input.length, 256, 0);
        assertEquals(0, rc);
        assertEquals("bac29cc3b2b03f661cbd74ade88c8336756706769e96376c7f0d875228595305", toHex(out));
    }

    // 한글 입력 SHA3-512(최적화, 지원 시 실행)
    @Test
    public void testOptimizedKorean512() {
        Assumptions.assumeTrue(isSha3Available(512));
        final Sha3Optimized optimized = new Sha3Optimized();
        final byte[] input = "테스트".getBytes(StandardCharsets.UTF_8);
        final byte[] digest = optimized.digest(input, 512);
        assertEquals(
            "1202c701bda679497bd9fae351efb4bc96656a4ba78b184711645515ce7aa410279865413bb67a8df2257ed866aa5f8688cc46a2f19e3ac9420197692b4fde18",
            toHex(digest));
    }

    // 이모지 입력 비교 (최적화 지원 시 실행)
    @Test
    public void testUnicodeOptimizedMatchesOriginal() {
        Assumptions.assumeTrue(isSha3Available(256));
        final sha3 original = new sha3();
        final Sha3Optimized optimized = new Sha3Optimized();
        final byte[] input = "emoji \uD83D\uDE00".getBytes(StandardCharsets.UTF_8);
        final byte[] expected = new byte[32];
        final int rc = original.sha3Hash(expected, expected.length, input, input.length, 256, 0);
        assertEquals(0, rc);
        final byte[] actual = optimized.digest(input, 256);
        assertArrayEquals(expected, actual);
        assertEquals("72a5ac0c9cbab2f48b1fc74e951d1102da6de1990c42d1610bfa2cee29e4f86f", toHex(actual));
    }

    // 모든 비트 길이 비교 (최적화 지원 시 실행)
    @Test
    public void testAllBitSizesMatch() {
        Assumptions.assumeTrue(isSha3Available(256));
        final sha3 original = new sha3();
        final Sha3Optimized optimized = new Sha3Optimized();
        final byte[] input = "OpenAI".getBytes(StandardCharsets.UTF_8);
        final int[] bitSizes = {224, 256, 384, 512};
        for (final int bit : bitSizes) {
            final byte[] expected = new byte[bit / 8];
            final int rc = original.sha3Hash(expected, expected.length, input, input.length, bit, 0);
            assertEquals(0, rc);
            final byte[] actual = optimized.digest(input, bit);
            assertArrayEquals(expected, actual, "bitSize=" + bit);
        }
    }
}
