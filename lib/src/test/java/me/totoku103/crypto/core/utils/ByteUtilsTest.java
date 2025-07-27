package me.totoku103.crypto.core.utils;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/** ByteUtils 클래스의 모든 기능을 테스트합니다. */
class ByteUtilsTest {

  @Test
  void testToHexString() {
    byte[] bytes = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    String hex = ByteUtils.toHexString(bytes);
    assertEquals("48656c6c6f", hex);
  }

  @Test
  void testToHexStringWithNull() {
    String hex = ByteUtils.toHexString(null);
    assertNull(hex);
  }

  @Test
  void testFromHexString() {
    String hex = "48656c6c6f";
    byte[] bytes = ByteUtils.fromHexString(hex);
    assertArrayEquals(new byte[] {0x48, 0x65, 0x6C, 0x6C, 0x6F}, bytes);
  }

  @Test
  void testFromHexStringWithInvalidLength() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          ByteUtils.fromHexString("123");
        });
  }

  @Test
  void testStringToHex() {
    String text = "Hello";
    String hex = ByteUtils.stringToHex(text);
    assertEquals("48656c6c6f", hex);
  }

  @Test
  void testStringToHexWithNull() {
    String hex = ByteUtils.stringToHex(null);
    assertNull(hex);
  }

  @Test
  void testHexToString() {
    String hex = "48656c6c6f";
    String text = ByteUtils.hexToString(hex);
    assertEquals("Hello", text);
  }

  @Test
  void testHexToStringWithNull() {
    String text = ByteUtils.hexToString(null);
    assertNull(text);
  }

  @Test
  void testCopy() {
    byte[] original = {1, 2, 3, 4, 5};
    byte[] copied = ByteUtils.copy(original);
    assertArrayEquals(original, copied);
    assertNotSame(original, copied);
  }

  @Test
  void testCopyWithNull() {
    byte[] copied = ByteUtils.copy(null);
    assertNull(copied);
  }

  @Test
  void testCopyWithOffset() {
    byte[] src = {1, 2, 3, 4, 5};
    byte[] dest = new byte[3];
    ByteUtils.copy(src, 1, dest, 0, 3);
    assertArrayEquals(new byte[] {2, 3, 4}, dest);
  }

  @Test
  void testIsEmpty() {
    assertTrue(ByteUtils.isEmpty(null));
    assertTrue(ByteUtils.isEmpty(new byte[0]));
    assertFalse(ByteUtils.isEmpty(new byte[] {1, 2, 3}));
  }

  @Test
  void testIsValid() {
    assertFalse(ByteUtils.isValid(null));
    assertFalse(ByteUtils.isValid(new byte[0]));
    assertTrue(ByteUtils.isValid(new byte[] {1, 2, 3}));
  }

  @Test
  void testAddPadding() {
    byte[] data = "Hello".getBytes();
    byte[] padded = ByteUtils.addPadding(data);
    assertEquals(16, padded.length);
    assertEquals(11, padded[padded.length - 1]); // PKCS7 padding
  }

  @Test
  void testAddPaddingWithCustomBlockSize() {
    byte[] data = "Hello".getBytes();
    byte[] padded = ByteUtils.addPadding(data, 8);
    assertEquals(8, padded.length);
    assertEquals(3, padded[padded.length - 1]); // PKCS7 padding
  }

  @Test
  void testAddPaddingWithNull() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          ByteUtils.addPadding(null);
        });
  }

  @Test
  void testAddPaddingWithInvalidBlockSize() {
    byte[] data = "Hello".getBytes();
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          ByteUtils.addPadding(data, 0);
        });
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          ByteUtils.addPadding(data, 256);
        });
  }

  @Test
  void testRemovePadding() {
    byte[] data = "Hello".getBytes();
    byte[] padded = ByteUtils.addPadding(data);
    byte[] unpadded = ByteUtils.removePadding(padded);
    assertArrayEquals(data, unpadded);
  }

  @Test
  void testRemovePaddingWithCustomBlockSize() {
    byte[] data = "Hello".getBytes();
    byte[] padded = ByteUtils.addPadding(data, 8);
    byte[] unpadded = ByteUtils.removePadding(padded, 8);
    assertArrayEquals(data, unpadded);
  }

  @Test
  void testRemovePaddingWithNull() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          ByteUtils.removePadding(null);
        });
  }

  @Test
  void testRemovePaddingWithEmptyArray() {
    // 빈 배열은 그대로 반환되어야 함
    byte[] result = ByteUtils.removePadding(new byte[0]);
    assertEquals(0, result.length);
  }

  @Test
  void testRemovePaddingWithInvalidLength() {
    byte[] data = {1, 2, 3, 4, 5}; // Not multiple of block size
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          ByteUtils.removePadding(data);
        });
  }

  @Test
  void testBytesToInt() {
    byte[] bytes = {0x12, 0x34, 0x56, 0x78};
    int value = ByteUtils.bytesToInt(bytes, 0);
    assertEquals(0x12345678, value);
  }

  @Test
  void testIntToBytes() {
    int value = 0x12345678;
    byte[] bytes = new byte[4];
    ByteUtils.intToBytes(value, bytes, 0);
    assertArrayEquals(new byte[] {0x12, 0x34, 0x56, 0x78}, bytes);
  }

  @Test
  void testBytesToLong() {
    byte[] bytes = {0x12, 0x34, 0x56, 0x78, (byte) 0x9A, (byte) 0xBC, (byte) 0xDE, (byte) 0xF0};
    long value = ByteUtils.bytesToLong(bytes, 0);
    assertEquals(0x123456789ABCDEF0L, value);
  }

  @Test
  void testLongToBytes() {
    long value = 0x123456789ABCDEF0L;
    byte[] bytes = new byte[8];
    ByteUtils.longToBytes(value, bytes, 0);
    assertArrayEquals(
        new byte[] {0x12, 0x34, 0x56, 0x78, (byte) 0x9A, (byte) 0xBC, (byte) 0xDE, (byte) 0xF0},
        bytes);
  }

  @Test
  void testRoundTripConversion() {
    // String -> Hex -> String
    String original = "Hello, World!";
    String hex = ByteUtils.stringToHex(original);
    String restored = ByteUtils.hexToString(hex);
    assertEquals(original, restored);

    // Bytes -> Hex -> Bytes
    byte[] originalBytes = original.getBytes();
    String hexBytes = ByteUtils.toHexString(originalBytes);
    byte[] restoredBytes = ByteUtils.fromHexString(hexBytes);
    assertArrayEquals(originalBytes, restoredBytes);

    // Int -> Bytes -> Int
    int originalInt = 0x12345678;
    byte[] intBytes = new byte[4];
    ByteUtils.intToBytes(originalInt, intBytes, 0);
    int restoredInt = ByteUtils.bytesToInt(intBytes, 0);
    assertEquals(originalInt, restoredInt);

    // Long -> Bytes -> Long
    long originalLong = 0x123456789ABCDEF0L;
    byte[] longBytes = new byte[8];
    ByteUtils.longToBytes(originalLong, longBytes, 0);
    long restoredLong = ByteUtils.bytesToLong(longBytes, 0);
    assertEquals(originalLong, restoredLong);
  }
}
