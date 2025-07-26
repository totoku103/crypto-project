package me.totoku103.crypto.utils;

import java.util.Arrays;

public class PaddingUtils {
  private static final int DEFAULT_BLOCK_SIZE = 16; // 블록 크기 (예: 16바이트)

  public static byte[] addPadding(byte[] data) {
    return addPadding(data, DEFAULT_BLOCK_SIZE);
  }

  public static byte[] removePadding(final byte[] data) {
    return removePadding(data, DEFAULT_BLOCK_SIZE);
  }

  public static byte[] addPadding(final byte[] data, final int blockSize) {
    if (blockSize <= 0 || blockSize > 255) {
      throw new IllegalArgumentException("Block size must be between 1 and 255");
    }

    final int paddingLength = blockSize - (data.length % blockSize);
    final byte[] paddedData = Arrays.copyOf(data, data.length + paddingLength);
    Arrays.fill(paddedData, data.length, paddedData.length, (byte) paddingLength);
    return paddedData;
  }

  public static byte[] removePadding(final byte[] data, final int blockSize) {
    if (blockSize <= 0 || blockSize > 255) {
      throw new IllegalArgumentException("Block size must be between 1 and 255");
    }

    final int paddingLength = data[data.length - 1];
    if (paddingLength < 1 || paddingLength > blockSize) {
      throw new IllegalArgumentException("Invalid padding");
    }
    return Arrays.copyOf(data, data.length - paddingLength);
  }
}
