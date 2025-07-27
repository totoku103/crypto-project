package me.totoku103.crypto.legacy.utils;

/**
 * @deprecated 이 클래스는 하위 호환성을 위해 유지됩니다. 
 * 새로운 코드에서는 {@link me.totoku103.crypto.core.utils.ByteUtils}를 사용하세요.
 */
@Deprecated
public class PaddingUtils {
    
    private static final int DEFAULT_BLOCK_SIZE = 16; // 블록 크기 (예: 16바이트)

    /**
     * PKCS7 패딩을 추가합니다.
     * @deprecated {@link me.totoku103.crypto.core.utils.ByteUtils#addPadding(byte[])}를 사용하세요.
     */
    @Deprecated
    public static byte[] addPadding(byte[] data) {
        return me.totoku103.crypto.core.utils.ByteUtils.addPadding(data);
    }

    /**
     * PKCS7 패딩을 제거합니다.
     * @deprecated {@link me.totoku103.crypto.core.utils.ByteUtils#removePadding(byte[])}를 사용하세요.
     */
    @Deprecated
    public static byte[] removePadding(final byte[] data) {
        return me.totoku103.crypto.core.utils.ByteUtils.removePadding(data);
    }

    /**
     * PKCS7 패딩을 추가합니다.
     * @deprecated {@link me.totoku103.crypto.core.utils.ByteUtils#addPadding(byte[], int)}를 사용하세요.
     */
    @Deprecated
    public static byte[] addPadding(final byte[] data, final int blockSize) {
        return me.totoku103.crypto.core.utils.ByteUtils.addPadding(data, blockSize);
    }

    /**
     * PKCS7 패딩을 제거합니다.
     * @deprecated {@link me.totoku103.crypto.core.utils.ByteUtils#removePadding(byte[], int)}를 사용하세요.
     */
    @Deprecated
    public static byte[] removePadding(final byte[] data, final int blockSize) {
        return me.totoku103.crypto.core.utils.ByteUtils.removePadding(data, blockSize);
    }
} 