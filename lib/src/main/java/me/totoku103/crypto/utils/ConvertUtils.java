package me.totoku103.crypto.utils;

public class ConvertUtils {
    // 16진수 문자열을 바이트 배열로 변환
    public static byte[] fromHex(final String hex) {
        final int len = hex.length();
        final byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    // 바이트 배열을 16진수 문자열로 변환
    public static String toHex(final byte[] data) {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
