package me.totoku103.crypto.legacy.utils;

import java.nio.charset.StandardCharsets;

/**
 * @deprecated 이 클래스는 하위 호환성을 위해 유지됩니다. 
 * 새로운 코드에서는 {@link me.totoku103.crypto.core.utils.ByteUtils}를 사용하세요.
 */
@Deprecated
public class HexConverter {
    
    /**
     * 바이트 배열을 16진수 문자열로 변환합니다.
     * @deprecated {@link me.totoku103.crypto.core.utils.ByteUtils#toHexString(byte[])}를 사용하세요.
     */
    @Deprecated
    public static String fromBytes(final byte[] data) {
        return me.totoku103.crypto.core.utils.ByteUtils.toHexString(data);
    }

    /**
     * 문자열을 16진수 문자열로 변환합니다.
     * @deprecated {@link me.totoku103.crypto.core.utils.ByteUtils#stringToHex(String)}를 사용하세요.
     */
    @Deprecated
    public static String fromString(String plainText) {
        return me.totoku103.crypto.core.utils.ByteUtils.stringToHex(plainText);
    }

    /**
     * 16진수 문자열을 문자열로 변환합니다.
     * @deprecated {@link me.totoku103.crypto.core.utils.ByteUtils#hexToString(String)}를 사용하세요.
     */
    @Deprecated
    public static String toString(String hex) {
        return me.totoku103.crypto.core.utils.ByteUtils.hexToString(hex);
    }

    /**
     * 16진수 문자열을 바이트 배열로 변환합니다.
     * @deprecated {@link me.totoku103.crypto.core.utils.ByteUtils#fromHexString(String)}를 사용하세요.
     */
    @Deprecated
    public static byte[] toBytes(final String hex) {
        return me.totoku103.crypto.core.utils.ByteUtils.fromHexString(hex);
    }
} 