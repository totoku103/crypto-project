package me.totoku103.crypto.core;

import static org.junit.jupiter.api.Assertions.*;

import me.totoku103.crypto.core.utils.ByteUtils;
import org.junit.jupiter.api.BeforeEach;

/** 모든 암호화 테스트의 기본 클래스 공통 테스트 데이터와 유틸리티 메서드를 제공합니다. */
public abstract class BaseCryptoTest {

  protected static final String TEST_STRING_1 = "Hello";
  protected static final String TEST_STRING_2 = "Hello, World!";
  protected static final String TEST_STRING_3 = "안녕하세요";
  protected static final String TEST_STRING_4 = "Test with spaces";
  protected static final String TEST_STRING_5 = "Special chars: !@#$%^&*()";

  protected static final byte[] TEST_KEY_16 = "1234567890123456".getBytes();
  protected static final byte[] TEST_KEY_32 = "12345678901234567890123456789012".getBytes();

  protected static final String[] TEST_STRINGS = {
    TEST_STRING_1, TEST_STRING_2, TEST_STRING_3, TEST_STRING_4
  };

  @BeforeEach
  void setUp() {
    // 각 테스트 전에 실행될 공통 설정
  }

  /** 바이트 배열이 유효한지 확인합니다. */
  protected void assertValidBytes(byte[] bytes, String message) {
    assertNotNull(bytes, message + " should not be null");
    assertTrue(bytes.length > 0, message + " should not be empty");
  }

  /** 16진수 문자열이 유효한지 확인합니다. */
  protected void assertValidHexString(String hex, int expectedLength, String message) {
    assertNotNull(hex, message + " should not be null");
    assertEquals(expectedLength, hex.length(), message + " should have correct length");
    assertTrue(hex.matches("[0-9a-f]+"), message + " should be valid hex string");
  }

  /** 암호화/복호화 결과가 원본과 일치하는지 확인합니다. */
  protected void assertEncryptDecryptMatch(byte[] original, byte[] decrypted, String message) {
    assertArrayEquals(original, decrypted, message + " should match original");
  }

  /** 테스트 데이터를 로그로 출력합니다. */
  protected void logTestData(String label, byte[] data) {
    System.out.println(label + " length: " + data.length);
    System.out.println(label + " hex: " + ByteUtils.toHexString(data));
    if (data.length <= 100) {
      System.out.println(label + " string: " + new String(data));
    }
  }

  /** 테스트 데이터를 로그로 출력합니다. */
  protected void logTestData(String label, String data) {
    System.out.println(label + " length: " + data.length());
    System.out.println(label + " content: " + data);
  }
}
