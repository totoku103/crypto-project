package me.totoku103.crypto.kisa.sha3.model;

import me.totoku103.crypto.kisa.sha3.enums.BitSizeType;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * JDK MessageDigest를 이용해 속도를 높인 SHA-3 구현입니다.
 */
public class Sha3MessageDigest {

    private static final int SHA3_OK = 0;
    private static final int SHA3_PARAMETER_ERROR = 1;

    /**
     * JDK에서 SHA3 알고리즘이 지원되는지 확인합니다.
     *
     * @param bitSize 224, 256, 384, 512 중 하나
     * @return SHA3 알고리즘이 지원되면 true, 그렇지 않으면 false
     */
    public static boolean isSha3Available(final BitSizeType bitSize) {
        try {
            java.security.MessageDigest.getInstance(bitSize.getAlgorithmName());
            return true;
        } catch (java.security.NoSuchAlgorithmException e) {
            return false;
        }
    }

    /**
     * JDK MessageDigest로 SHA3 해시를 계산합니다.
     *
     * @param output      결과 버퍼
     * @param outLen      출력 길이(byte)
     * @param input       입력 데이터
     * @param inLen       입력 길이
     * @param bitSizeType 224, 256, 384, 512 중 하나
     * @return 성공하면 0
     */
    public int sha3Hash(final byte[] output, final int outLen, final byte[] input, final int inLen, final BitSizeType bitSizeType) {
        try {
            final MessageDigest md = MessageDigest.getInstance(bitSizeType.getAlgorithmName());
            md.update(input, 0, inLen);
            final byte[] digest = md.digest();
            if (digest.length != outLen) {
                return SHA3_PARAMETER_ERROR;
            }
            System.arraycopy(digest, 0, output, 0, outLen);
            return SHA3_OK;
        } catch (NoSuchAlgorithmException e) {
            return SHA3_PARAMETER_ERROR;
        }
    }

    /**
     * 새 배열로 해시 값을 돌려줍니다.
     */
    public byte[] toHash(final byte[] input, final BitSizeType bitSizeType) {
        try {
            final MessageDigest md = MessageDigest.getInstance(bitSizeType.getAlgorithmName());
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported " + bitSizeType.getAlgorithmName(), e);
        }
    }
}
