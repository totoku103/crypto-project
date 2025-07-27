package me.totoku103.crypto.java.seed;

import me.totoku103.crypto.VectorFileTestSupport;
import me.totoku103.crypto.core.utils.ByteUtils;
import me.totoku103.crypto.enums.SeedCbcTransformations;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.util.List;
import java.util.stream.Stream;

/**
 * https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do 의 테스트벡터 파일을 읽어와서 SEED CBC 모드를 테스트한다. 기본
 * 제공된 데이터는 NonPadding 모드.
 */
class SeedCbcMmtVectorFileTest extends VectorFileTestSupport {
    static class TestVectorMmt {
        private String key;
        private String iv;
        private String pt;
        private String ct;
    }

    public static Stream<TestVectorMmt> getTestVectors() throws IOException {
        final URL resource =
                SeedCbcMmtVectorFileTest.class.getResource("/testvectors/seedcbc/SEED-128_(CBC)_MMT.txt");
        Assertions.assertNotNull(resource);
        final File katFile = new File(resource.getFile());
        if (!katFile.isFile()) throw new RuntimeException("kat file is not a file");
        final List<String> strings = Files.readAllLines(katFile.toPath());

        final List<TestVectorMmt> testVectors = new java.util.ArrayList<>();
        TestVectorMmt current = null;
        for (String line : strings) {
            line = line.trim();
            if (line.isEmpty()) continue;

            if (line.startsWith("KEY =")) {
                current = new TestVectorMmt();
                testVectors.add(current);
                current.key = getSplitAndValue(line);
            } else if (line.startsWith("IV =")) current.iv = getSplitAndValue(line);
            else if (line.startsWith("PT =")) current.pt = getSplitAndValue(line);
            else if (line.startsWith("CT =")) current.ct = getSplitAndValue(line);
        }
        return testVectors.stream();
    }

    @ParameterizedTest
    @MethodSource("getTestVectors")
    public void testKatVectors(TestVectorMmt vector) {
        final String key = vector.key;
        final String iv = vector.iv;
        final String pt = vector.pt;
        final String ct = vector.ct;

        final byte[] keyBytes = ByteUtils.fromHexString(key);
        final byte[] ivBytes = ByteUtils.fromHexString(iv);
        final byte[] ptBytes = ByteUtils.fromHexString(pt);
        final byte[] ctBytes = ByteUtils.fromHexString(ct);

        final SeedCbc seedCbc = new SeedCbc(SeedCbcTransformations.SEED_CBC_NO_PADDING);
        final byte[] encrypted = seedCbc.encrypt(ptBytes, keyBytes, ivBytes);
        Assertions.assertArrayEquals(ctBytes, encrypted);

        final byte[] decrypted = seedCbc.decrypt(encrypted, keyBytes, ivBytes);
        Assertions.assertArrayEquals(ptBytes, decrypted);
    }
}
