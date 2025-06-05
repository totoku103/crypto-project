package me.totoku103.crypto.kisa.sha3;

import me.totoku103.crypto.kisa.sha3.model.Sha3Vanilla;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Sha3VanillaTest {

    // 바이트 배열을 16진수 문자열로 변환
    private static String toHex(final byte[] data) {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Test
    @DisplayName("SHA3-256 벡터 테스트")
    public void testSha3256Vector() {
        final Sha3Vanilla hasher = new Sha3Vanilla();
        final byte[] input = "abc".getBytes(StandardCharsets.UTF_8);
        final byte[] out = new byte[32];
        final int rc = hasher.toHash(out, out.length, input, input.length, 256, 0);
        assertEquals(0, rc);
        assertEquals("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", toHex(out));
    }

    @Test
    @DisplayName("한글 입력 SHA3-256")
    public void testKoreanVector256() {
        final Sha3Vanilla hasher = new Sha3Vanilla();
        final byte[] input = "안녕하세요".getBytes(StandardCharsets.UTF_8);
        final byte[] out = new byte[32];
        final int rc = hasher.toHash(out, out.length, input, input.length, 256, 0);
        assertEquals(0, rc);
        assertEquals("bac29cc3b2b03f661cbd74ade88c8336756706769e96376c7f0d875228595305", toHex(out));
    }
}
