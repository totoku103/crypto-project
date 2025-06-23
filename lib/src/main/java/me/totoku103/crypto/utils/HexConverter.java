package me.totoku103.crypto.utils;

import java.nio.charset.StandardCharsets;

public class HexConverter {
    // 바이트 배열을 16진수 문자열로 변환
    public static String fromBytes(final byte[] data) {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String fromString(String plainText) {
        final StringBuilder hex = new StringBuilder();
        final byte[] bytes = plainText.getBytes(StandardCharsets.UTF_8);

        for (byte b : bytes) {
            hex.append(String.format("%02x", b)); // 2자리 hex, 소문자
        }

        return hex.toString();
    }

    public static String toString(String hex) {
        final StringBuilder result = new StringBuilder();

        for (int i = 0; i < hex.length(); i += 2) {
            String byteStr = hex.substring(i, i + 2);
            int byteVal = Integer.parseInt(byteStr, 16);
            result.append((char) byteVal);
        }

        return result.toString();
    }

    public static byte[] toBytes(final String hex) {
        final int len = hex.length();
        final byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}
