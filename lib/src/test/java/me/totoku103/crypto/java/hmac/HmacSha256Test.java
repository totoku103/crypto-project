package me.totoku103.crypto.java.hmac;

import me.totoku103.crypto.kisa.hmac.KISA_HMAC;
import me.totoku103.crypto.kisa.hmac.Utils;
import me.totoku103.crypto.utils.HexConverter;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class HmacSha256Test {

    private HmacSha256 hmac;

    @BeforeEach
    void setUp() {
        this.hmac = new HmacSha256();
    }

    @Test
    @DisplayName("JDK에서 HmacSHA256 지원 여부 확인")
    void isHmacSha256Available() {
        assertTrue(HmacSha256.isHmacSha256Available());
    }

    @Test
    @DisplayName("RFC 4231 테스트 벡터 #1 검증")
    void testVector1() {
        Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());
        byte[] key = new byte[20];
        java.util.Arrays.fill(key, (byte) 0x0b);
        byte[] data = "Hi There".getBytes(StandardCharsets.UTF_8);
        byte[] expected = HexConverter.toBytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        byte[] out = new byte[32];

        int rc = hmac.hmacSha256(out, out.length, key, key.length, data, data.length);
        assertEquals(0, rc);
        assertArrayEquals(expected, out);
    }

    @Test
    @DisplayName("RFC 4231 테스트 벡터 #2 검증")
    void testVector2() {
        Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());
        byte[] key = "Jefe".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] data = "what do ya want for nothing?".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] expected = HexConverter.toBytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        byte[] out = new byte[32];

        int rc = hmac.hmacSha256(out, out.length, key, key.length, data, data.length);
        assertEquals(0, rc);
        assertArrayEquals(expected, out);
    }

    @Test
    @DisplayName("RFC 4231 테스트 벡터 #3 검증")
    void testVector3() {
        Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());
        byte[] key = new byte[20];
        java.util.Arrays.fill(key, (byte) 0xaa);
        byte[] data = new byte[50];
        java.util.Arrays.fill(data, (byte) 0xdd);
        byte[] expected = HexConverter.toBytes("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
        byte[] out = new byte[32];

        int rc = hmac.hmacSha256(out, out.length, key, key.length, data, data.length);
        assertEquals(0, rc);
        assertArrayEquals(expected, out);
    }

    @Test
    @DisplayName("RFC 4231 테스트 벡터 #4 검증")
    void testVector4() {
        Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());
        byte[] key = new byte[25];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (i + 1);
        }
        byte[] data = new byte[50];
        java.util.Arrays.fill(data, (byte) 0xcd);
        byte[] expected = HexConverter.toBytes("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
        byte[] out = new byte[32];

        int rc = hmac.hmacSha256(out, out.length, key, key.length, data, data.length);
        assertEquals(0, rc);
        assertArrayEquals(expected, out);
    }

    @Test
    public void testCompare() {
        Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());
        byte[] key = new byte[25];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (i + 1);
        }
        byte[] data = new byte[50];
        java.util.Arrays.fill(data, (byte) 0xcd);
        byte[] expected = HexConverter.toBytes("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
        byte[] out = new byte[32];

        int rc = hmac.hmacSha256(out, out.length, key, key.length, data, data.length);
        assertEquals(0, rc);
        assertArrayEquals(expected, out);
        System.out.println(new String(out, StandardCharsets.UTF_8));

        byte[] out2 = new byte[32];
        KISA_HMAC.HMAC_SHA256_Transform(out2, key, key.length, data, data.length);
        assertArrayEquals(expected, out2);
        System.out.println(new String(out2, StandardCharsets.UTF_8));
    }

    private static String getSplitAndValue(String line) {
        final String[] split = line.split("=");
        if (split.length == 1) return "";
        else if (split.length == 2) return split[1].trim();
        else return "";
    }

    static class HMac {
        private int count;
        private int kLen;
        private int tLen;
        private String key;
        private String msg;
        private String mac;
    }

    public static Stream<HMac> readTestVectors() throws IOException {
        final URL resource = HmacSha256Test.class.getResource("/testvectors/hmac/HMAC_SHA-256_KAT.txt");
        Assertions.assertNotNull(resource);
        final File file = new File(resource.getFile());
        final List<String> lines = Files.readAllLines(Paths.get(file.getPath()));

        final List<HMac> testVectors = new ArrayList<>();
        HMac current = null;

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) continue;

            if (line.startsWith("COUNT =")) {
                if (current != null) testVectors.add(current);
                current = new HMac();
                current.count = Integer.parseInt(getSplitAndValue(line));
            } else if (line.startsWith("Klen =")) {
                current.kLen = Integer.parseInt(getSplitAndValue(line));
            } else if (line.startsWith("Tlen = ")) {
                current.tLen = Integer.parseInt(getSplitAndValue(line));
            } else if (line.startsWith("Key =")) {
                current.key = getSplitAndValue(line);
            } else if (line.startsWith("Msg =")) {
                current.msg = getSplitAndValue(line);
            } else if (line.startsWith("Mac =")) {
                current.mac = getSplitAndValue(line);
            }
        }

        return testVectors.stream();
    }

    @ParameterizedTest
    @MethodSource("readTestVectors")
    public void test(HMac vector) {
//        Assumptions.assumeTrue(vector.tLen == 32);

        final byte[] keyBytes = HexConverter.toBytes(vector.key);
        final byte[] messageBytes = HexConverter.toBytes(vector.msg);
        final byte[] ctBytes = HexConverter.toBytes(vector.mac);

        final byte[] output = new byte[vector.tLen];

        hmac.hmacSha256(output, output.length, keyBytes, vector.kLen, messageBytes, messageBytes.length);
        final String s = HexConverter.fromBytes(output);
        Utils.print_hex("output", output, output.length);
        System.out.println("a: " + s + "\nb: " + vector.mac);
        Assertions.assertEquals(s.toUpperCase(), vector.mac.toUpperCase());
    }
}
