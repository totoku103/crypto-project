package me.totoku103.crypto.core.utils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * 바이트 조작을 위한 유틸리티 클래스
 */
public final class ByteUtils {
    
    private static final int DEFAULT_BLOCK_SIZE = 16; // 기본 블록 크기
    
    private ByteUtils() {
        // 유틸리티 클래스는 인스턴스화하지 않음
    }
    
    // ==================== 16진수 변환 메서드 ====================
    
    /**
     * 바이트 배열을 16진수 문자열로 변환합니다.
     * @param bytes 변환할 바이트 배열
     * @return 16진수 문자열
     */
    public static String toHexString(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
    
    /**
     * 16진수 문자열을 바이트 배열로 변환합니다.
     * @param hexString 16진수 문자열
     * @return 바이트 배열
     */
    public static byte[] fromHexString(String hexString) {
        if (hexString == null || hexString.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string");
        }
        
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }
    
    /**
     * 문자열을 16진수 문자열로 변환합니다.
     * @param plainText 변환할 문자열
     * @return 16진수 문자열
     */
    public static String stringToHex(String plainText) {
        if (plainText == null) {
            return null;
        }
        
        byte[] bytes = plainText.getBytes(StandardCharsets.UTF_8);
        return toHexString(bytes);
    }
    
    /**
     * 16진수 문자열을 문자열로 변환합니다.
     * @param hex 16진수 문자열
     * @return 변환된 문자열
     */
    public static String hexToString(String hex) {
        if (hex == null) {
            return null;
        }
        
        byte[] bytes = fromHexString(hex);
        return new String(bytes, StandardCharsets.UTF_8);
    }
    
    // ==================== 바이트 배열 조작 메서드 ====================
    
    /**
     * 바이트 배열을 복사합니다.
     * @param src 원본 배열
     * @param srcPos 원본 시작 위치
     * @param dest 대상 배열
     * @param destPos 대상 시작 위치
     * @param length 복사할 길이
     */
    public static void copy(byte[] src, int srcPos, byte[] dest, int destPos, int length) {
        System.arraycopy(src, srcPos, dest, destPos, length);
    }
    
    /**
     * 바이트 배열을 복사합니다.
     * @param src 원본 배열
     * @return 복사된 배열
     */
    public static byte[] copy(byte[] src) {
        if (src == null) {
            return null;
        }
        byte[] dest = new byte[src.length];
        System.arraycopy(src, 0, dest, 0, src.length);
        return dest;
    }
    
    /**
     * 바이트 배열이 null이거나 비어있는지 확인합니다.
     * @param bytes 확인할 바이트 배열
     * @return null이거나 비어있으면 true
     */
    public static boolean isEmpty(byte[] bytes) {
        return bytes == null || bytes.length == 0;
    }
    
    /**
     * 바이트 배열이 유효한지 확인합니다.
     * @param bytes 확인할 바이트 배열
     * @return null이 아니고 비어있지 않으면 true
     */
    public static boolean isValid(byte[] bytes) {
        return !isEmpty(bytes);
    }
    
    // ==================== 패딩 메서드 ====================
    
    /**
     * PKCS7 패딩을 추가합니다.
     * @param data 원본 데이터
     * @return 패딩이 추가된 데이터
     */
    public static byte[] addPadding(byte[] data) {
        return addPadding(data, DEFAULT_BLOCK_SIZE);
    }
    
    /**
     * PKCS7 패딩을 제거합니다.
     * @param data 패딩이 포함된 데이터
     * @return 패딩이 제거된 데이터
     */
    public static byte[] removePadding(byte[] data) {
        return removePadding(data, DEFAULT_BLOCK_SIZE);
    }
    
    /**
     * PKCS7 패딩을 추가합니다.
     * @param data 원본 데이터
     * @param blockSize 블록 크기
     * @return 패딩이 추가된 데이터
     */
    public static byte[] addPadding(byte[] data, int blockSize) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        
        if (blockSize <= 0 || blockSize > 255) {
            throw new IllegalArgumentException("Block size must be between 1 and 255");
        }
        
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] paddedData = Arrays.copyOf(data, data.length + paddingLength);
        Arrays.fill(paddedData, data.length, paddedData.length, (byte) paddingLength);
        return paddedData;
    }
    
    /**
     * PKCS7 패딩을 제거합니다.
     * @param data 패딩이 포함된 데이터
     * @param blockSize 블록 크기
     * @return 패딩이 제거된 데이터
     */
    public static byte[] removePadding(byte[] data, int blockSize) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        
        if (blockSize <= 0 || blockSize > 255) {
            throw new IllegalArgumentException("Block size must be between 1 and 255");
        }
        
        if (data.length % blockSize != 0) {
            throw new IllegalArgumentException("Data length must be a multiple of block size");
        }
        
        int paddingLength = data[data.length - 1] & 0xFF;
        if (paddingLength < 1 || paddingLength > blockSize) {
            throw new IllegalArgumentException("Invalid padding length: " + paddingLength);
        }
        
        // 패딩 바이트들이 모두 동일한 값인지 확인
        for (int i = data.length - paddingLength; i < data.length; i++) {
            if ((data[i] & 0xFF) != paddingLength) {
                throw new IllegalArgumentException("Invalid padding");
            }
        }
        
        return Arrays.copyOf(data, data.length - paddingLength);
    }
    
    // ==================== 유틸리티 메서드 ====================
    
    /**
     * 바이트 배열을 int로 변환합니다 (Big Endian).
     * @param bytes 바이트 배열
     * @param offset 시작 위치
     * @return 변환된 int 값
     */
    public static int bytesToInt(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 24) |
               ((bytes[offset + 1] & 0xFF) << 16) |
               ((bytes[offset + 2] & 0xFF) << 8) |
               (bytes[offset + 3] & 0xFF);
    }
    
    /**
     * int를 바이트 배열로 변환합니다 (Big Endian).
     * @param value 변환할 int 값
     * @param bytes 대상 바이트 배열
     * @param offset 시작 위치
     */
    public static void intToBytes(int value, byte[] bytes, int offset) {
        bytes[offset] = (byte) ((value >> 24) & 0xFF);
        bytes[offset + 1] = (byte) ((value >> 16) & 0xFF);
        bytes[offset + 2] = (byte) ((value >> 8) & 0xFF);
        bytes[offset + 3] = (byte) (value & 0xFF);
    }
    
    /**
     * 바이트 배열을 long으로 변환합니다 (Big Endian).
     * @param bytes 바이트 배열
     * @param offset 시작 위치
     * @return 변환된 long 값
     */
    public static long bytesToLong(byte[] bytes, int offset) {
        return ((long) (bytes[offset] & 0xFF) << 56) |
               ((long) (bytes[offset + 1] & 0xFF) << 48) |
               ((long) (bytes[offset + 2] & 0xFF) << 40) |
               ((long) (bytes[offset + 3] & 0xFF) << 32) |
               ((long) (bytes[offset + 4] & 0xFF) << 24) |
               ((long) (bytes[offset + 5] & 0xFF) << 16) |
               ((long) (bytes[offset + 6] & 0xFF) << 8) |
               (bytes[offset + 7] & 0xFF);
    }
    
    /**
     * long을 바이트 배열로 변환합니다 (Big Endian).
     * @param value 변환할 long 값
     * @param bytes 대상 바이트 배열
     * @param offset 시작 위치
     */
    public static void longToBytes(long value, byte[] bytes, int offset) {
        bytes[offset] = (byte) ((value >> 56) & 0xFF);
        bytes[offset + 1] = (byte) ((value >> 48) & 0xFF);
        bytes[offset + 2] = (byte) ((value >> 40) & 0xFF);
        bytes[offset + 3] = (byte) ((value >> 32) & 0xFF);
        bytes[offset + 4] = (byte) ((value >> 24) & 0xFF);
        bytes[offset + 5] = (byte) ((value >> 16) & 0xFF);
        bytes[offset + 6] = (byte) ((value >> 8) & 0xFF);
        bytes[offset + 7] = (byte) (value & 0xFF);
    }
} 