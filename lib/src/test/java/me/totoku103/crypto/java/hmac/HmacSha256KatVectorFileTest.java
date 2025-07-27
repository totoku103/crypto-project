package me.totoku103.crypto.java.hmac;

import me.totoku103.crypto.VectorFileTestSupport;
import me.totoku103.crypto.core.utils.ByteUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class HmacSha256KatVectorFileTest extends VectorFileTestSupport {


    static class TestVectorKat {
        private int count;
        private int kLen;
        private int tLen;

        private String key;
        private String msg;
        private String mac;

        public static TestVectorKat setValue(Map<String, String> v) {
            final TestVectorKat testVectorKat = new TestVectorKat();
            testVectorKat.count = Integer.parseInt(v.get("COUNT"));
            testVectorKat.kLen = Integer.parseInt(v.get("KLEN"));
            testVectorKat.tLen = Integer.parseInt(v.get("TLEN"));

            testVectorKat.key = v.get("KEY");
            testVectorKat.msg = v.get("MSG");
            testVectorKat.mac = v.get("MAC");
            return testVectorKat;
        }

        @Override
        public String toString() {
            return "TestVectorKat{" +
                    "count=" + count +
                    ", kLen=" + kLen +
                    ", tLen=" + tLen +
                    ", key='" + key + '\'' +
                    ", msg='" + msg + '\'' +
                    ", mac='" + mac + '\'' +
                    '}';
        }
    }

    public static Stream<TestVectorKat> providerSource() throws IOException {
        final File vectorFile = getVectorFile("/testvectors/hmac/HMAC_SHA-256_KAT.txt");
        final List<String> contents = getContents(vectorFile);
        final List<Map<String, String>> extracted = extractValue("=", contents);
        final List<TestVectorKat> collect = extracted.stream().filter(d -> d.size() == 6).map(TestVectorKat::setValue).collect(Collectors.toList());
        return collect.stream();
    }

    @ParameterizedTest(name = "[{0} - Hmac VectorFileTest")
    @MethodSource("providerSource")
    public void testVectorFiles(TestVectorKat vector) {
        final String key = vector.key;
        final String msg = vector.msg;
        final String mac = vector.mac;

        final byte[] keyBytes = ByteUtils.fromHexString(key);
        final byte[] msgBytes = ByteUtils.fromHexString(msg);
        final byte[] macBytes = ByteUtils.fromHexString(mac);

        final HmacSha256 hmacSha256 = new HmacSha256();
        final byte[] output = new byte[vector.tLen];
        Assertions.assertEquals(vector.kLen, keyBytes.length);

        final int i = hmacSha256.hmacSha256(output, output.length, keyBytes, keyBytes.length, msgBytes, msgBytes.length);
        Assertions.assertArrayEquals(macBytes, output);
    }

}
