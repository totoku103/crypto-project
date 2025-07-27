package me.totoku103.crypto.java.seed;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import me.totoku103.crypto.VectorFileTestSupport;
import me.totoku103.crypto.core.utils.ByteUtils;
import me.totoku103.crypto.enums.SeedCbcTransformations;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do 의 테스트벡터 파일을 읽어와서 SEED CBC 모드를 테스트한다. 기본
 * 제공된 데이터는 NonPadding 모드.
 */
class SeedCbcKatVectorFileTest extends VectorFileTestSupport {
    static class TestVectorKat {
        private String key;
        private String iv;
        private String pt;
        private String ct;
    }

    public static Stream<TestVectorKat> getTestKatVectors() throws IOException {
        final URL resource =
                SeedCbcKatVectorFileTest.class.getResource("/testvectors/seedcbc/SEED-128_(CBC)_KAT.txt");
        Assertions.assertNotNull(resource);
        final File katFile = new File(resource.getFile());
        if (!katFile.isFile()) throw new RuntimeException("kat file is not a file");
        final List<String> strings = Files.readAllLines(katFile.toPath());

        final List<TestVectorKat> testVectors = new java.util.ArrayList<>();
        TestVectorKat current = null;
        for (String line : strings) {
            line = line.trim();
            if (line.isEmpty()) continue;

            if (line.startsWith("KEY =")) {
                current = new TestVectorKat();
                testVectors.add(current);
                current.key = getSplitAndValue(line);
            } else if (line.startsWith("IV =")) current.iv = getSplitAndValue(line);
            else if (line.startsWith("PT =")) current.pt = getSplitAndValue(line);
            else if (line.startsWith("CT =")) current.ct = getSplitAndValue(line);
        }
        return testVectors.stream();
    }

    @ParameterizedTest
    @MethodSource("getTestKatVectors")
    public void testKatVectors(TestVectorKat vector) {
        final String key = vector.key;
        final String iv = vector.iv;
        final String pt = vector.pt;
        final String ct = vector.ct;

        final byte[] keyBytes = ByteUtils.fromHexString(key);
        final byte[] ivBytes = ByteUtils.fromHexString(iv);
        final byte[] ptBytes = ByteUtils.fromHexString(pt);
        final byte[] ctBytes = ByteUtils.fromHexString(ct);

        final SeedCbc seedCbc = new SeedCbc(SeedCbcTransformations.SEED_CBC_NO_PADDING);
        final byte[] encrypt = seedCbc.encrypt(ptBytes, keyBytes, ivBytes);
        Assertions.assertArrayEquals(ctBytes, encrypt);

        final byte[] decrypt = seedCbc.decrypt(encrypt, keyBytes, ivBytes);
        Assertions.assertArrayEquals(ptBytes, decrypt);
    }

    @Test
    public void testKatVectors2() {
        final SecureRandom keyRandom = new SecureRandom();
        final byte[] keyBytes = new byte[16];
        keyRandom.nextBytes(keyBytes);
        final SecretKeySpec seedKey = new SecretKeySpec(keyBytes, "SEED");

        final SecureRandom ivRandom = new SecureRandom();
        final byte[] ivBytes = new byte[16];
        ivRandom.nextBytes(ivBytes);
        final IvParameterSpec securityIv = new IvParameterSpec(ivBytes);

        final String pt = "가나다라마바사아자차카타파하 동해물과 백두산이 마르고 닳도록";

        final SeedCbc seedCbc1 = new SeedCbc(SeedCbcTransformations.SEED_CBC_PKCS7_PADDING);
        final byte[] encrypt =
                seedCbc1.encrypt(
                        pt.getBytes(StandardCharsets.UTF_8), seedKey.getEncoded(), securityIv.getIV());
        final String base64Encrypt = Base64.getEncoder().encodeToString(encrypt);
        System.out.println(ByteUtils.toHexString(encrypt));
        System.out.println(base64Encrypt);

        final byte[] decode = Base64.getDecoder().decode(base64Encrypt);
        final SeedCbc seedCbc2 = new SeedCbc(SeedCbcTransformations.SEED_CBC_PKCS7_PADDING);
        final byte[] decrypt = seedCbc2.decrypt(decode, seedKey.getEncoded(), securityIv.getIV());

        System.out.println(new String(decrypt));
    }
}
