package me.totoku103.crypto.kisa.sha3;

import me.totoku103.crypto.kisa.sha3.enums.BitSizeType;
import me.totoku103.crypto.kisa.sha3.model.Sha3MessageDigest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

class Sha3Test {

    @Test
    @DisplayName("BitSizeType별 MessageDigest 인스턴스 생성 가능 여부 검증")
    public void testMessageDigestInstanceCreationByBitSizeType() {
        Assumptions.assumeTrue(Sha3MessageDigest.isSha3Available(BitSizeType.SHA3_224));
        Arrays.asList(BitSizeType.values())
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
}