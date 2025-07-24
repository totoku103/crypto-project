package me.totoku103.crypto.kisa.seed;

import me.totoku103.crypto.kisa.seed.mode.SeedGcm;
import me.totoku103.crypto.utils.HexConverter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SeedGcmVectorTest {
    static class TestVector {
        int count;
        String key;
        String iv;
        String pt;
        String adata;
        String c;
        String t;
    }

    static Stream<TestVector> testVectors() throws IOException {
        final List<TestVector> vectors = new ArrayList<>();
        final URL resource = SeedGcmVectorTest.class.getResource("/testvectors/seedgcm/GCM_SEED-128_AE.txt");
        Assertions.assertNotNull(resource);
        final File file = new File(resource.getPath());
        final List<String> lines = Files.readAllLines(file.toPath());

        TestVector current = null;

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) continue;

            if (line.startsWith("COUNT =")) {
                if (current != null) vectors.add(current);
                current = new TestVector();
                current.count = Integer.parseInt(line.split("=")[1].trim());
            } else if (line.startsWith("Key ="))
                current.key = getSplitAndValue(line);
            else if (line.startsWith("IV ="))
                current.iv = getSplitAndValue(line);
            else if (line.startsWith("PT ="))
                current.pt = getSplitAndValue(line);
            else if (line.startsWith("Adata ="))
                current.adata = getSplitAndValue(line);
            else if (line.startsWith("C ="))
                current.c = getSplitAndValue(line);
            else if (line.startsWith("T ="))
                current.t = getSplitAndValue(line);
        }

        if (current != null) vectors.add(current);
        return vectors.stream();
    }

    private static String getSplitAndValue(String line) {
        final String[] split = line.split("=");
        if (split.length == 1) return "";
        else if (split.length == 2) return split[1].trim();
        else return "";
    }


    @ParameterizedTest
    @MethodSource("testVectors")
    public void vectorTest(TestVector testVector) {
        byte[] key = HexConverter.toBytes(testVector.key);
        byte[] iv = HexConverter.toBytes(testVector.iv);
        byte[] aad = HexConverter.toBytes(testVector.adata);           // 추가 인증 데이터
        byte[] pt = HexConverter.toBytes(testVector.pt);           // 평문
        byte[] expectedTag = HexConverter.toBytes(testVector.t);
        int macLen = 16;

        final SeedGcm seedGcm = new SeedGcm();
        byte[] ctWithTag = new byte[pt.length + macLen];
        seedGcm.encryptionGcm(ctWithTag, pt, pt.length, macLen, iv, iv.length, aad, aad.length, key);

        // 암호문과 태그 분리
        byte[] ct = new byte[pt.length];
        byte[] tag = new byte[macLen];
        System.arraycopy(ctWithTag, 0, ct, 0, pt.length);
        System.arraycopy(ctWithTag, pt.length, tag, 0, macLen);

        // 태그 검증
        assertArrayEquals(expectedTag, tag);

        // 복호화 및 평문 검증
        byte[] decryptedPt = new byte[pt.length];
        int decryptedLen = seedGcm.decryptionGcm(decryptedPt, ctWithTag, ctWithTag.length, macLen, iv, iv.length, aad, aad.length, key);

        assertEquals(pt.length, decryptedLen);
        assertArrayEquals(pt, decryptedPt);
    }
}