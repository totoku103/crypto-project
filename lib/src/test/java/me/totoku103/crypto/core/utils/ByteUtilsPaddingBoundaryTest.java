package me.totoku103.crypto.core.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ByteUtils PKCS7 패딩 관련 경계값 분석 및 예외/오류 경로 테스트.
 *
 * <p>경계 조건:
 * <ul>
 *   <li>blockSize 최솟값(1) 및 최댓값(255)</li>
 *   <li>입력 길이 == blockSize (정확히 한 블록)</li>
 *   <li>조작된 패딩 바이트로 인한 예외 경로</li>
 * </ul>
 */
@DisplayName("ByteUtils PKCS7 패딩 경계값 분석 테스트")
class ByteUtilsPaddingBoundaryTest {

  // ==================== blockSize = 1 경계 ====================

  @Test
  @DisplayName("blockSize=1: 1바이트 입력 addPadding → 길이 2, 모든 바이트가 0x01")
  void addPadding_blockSize1_1byteInput_returns2BytesAllPaddingOne() {
    // Arrange
    byte[] input = new byte[] {(byte) 0x41}; // 'A'
    int blockSize = 1;

    // Act
    byte[] padded = ByteUtils.addPadding(input, blockSize);

    // Assert
    // blockSize=1 이면 paddingLength = 1 - (1 % 1) = 1 - 0 = 1
    // 결과: 원본 1 byte + 패딩 1 byte(값 0x01) = 2 bytes
    assertEquals(2, padded.length, "blockSize=1이면 항상 패딩 1바이트가 추가되어야 한다");
    assertEquals(0x41, padded[0] & 0xFF, "원본 데이터 바이트가 보존되어야 한다");
    assertEquals(0x01, padded[1] & 0xFF, "패딩 바이트 값이 0x01이어야 한다");
  }

  @Test
  @DisplayName("blockSize=1: 패딩된 2바이트 removePadding → 원문 1바이트 복원")
  void removePadding_blockSize1_paddedInput_restores1ByteOriginal() {
    // Arrange
    byte[] input = new byte[] {(byte) 0x41}; // 'A'
    int blockSize = 1;

    // Act
    byte[] padded = ByteUtils.addPadding(input, blockSize);
    byte[] restored = ByteUtils.removePadding(padded, blockSize);

    // Assert
    assertArrayEquals(input, restored, "원문 1바이트가 정확히 복원되어야 한다");
  }

  // ==================== blockSize = 255 경계 ====================

  @Test
  @DisplayName("blockSize=255(최대): 1바이트 입력 addPadding → 255바이트, 마지막 254바이트가 0xFE")
  void addPadding_blockSize255_1byteInput_returns255BytesWithPadding0xFE() {
    // Arrange
    byte[] input = new byte[] {(byte) 0x5A}; // 'Z'
    int blockSize = 255;

    // Act
    byte[] padded = ByteUtils.addPadding(input, blockSize);

    // Assert
    // paddingLength = 255 - (1 % 255) = 255 - 1 = 254
    // 결과: 원본 1 byte + 패딩 254 bytes(값 0xFE) = 255 bytes
    assertEquals(255, padded.length, "결과는 255바이트여야 한다");
    assertEquals(0x5A, padded[0] & 0xFF, "첫 바이트는 원본 데이터여야 한다");
    for (int i = 1; i < 255; i++) {
      assertEquals(0xFE, padded[i] & 0xFF,
          "인덱스 " + i + "의 패딩 바이트 값이 0xFE(254)이어야 한다");
    }
  }

  @Test
  @DisplayName("blockSize=255(최대): 패딩된 255바이트 removePadding → 원문 1바이트 복원")
  void removePadding_blockSize255_paddedInput_restores1ByteOriginal() {
    // Arrange
    byte[] input = new byte[] {(byte) 0x5A}; // 'Z'
    int blockSize = 255;

    // Act
    byte[] padded = ByteUtils.addPadding(input, blockSize);
    byte[] restored = ByteUtils.removePadding(padded, blockSize);

    // Assert
    assertArrayEquals(input, restored, "원문 1바이트가 정확히 복원되어야 한다");
  }

  // ==================== 입력 길이 == blockSize 경계 ====================

  @Test
  @DisplayName("입력 길이 == blockSize(16바이트): addPadding → 32바이트, 후반 16바이트 모두 0x10")
  void addPadding_inputLengthEqualsBlockSize_addsFullPaddingBlock() {
    // Arrange
    // 정확히 16바이트인 입력: PKCS7은 '이미 정렬된 경우 전체 블록 패딩 추가' 규칙을 따른다
    byte[] input = new byte[16];
    for (int i = 0; i < 16; i++) {
      input[i] = (byte) (i + 1); // 0x01 ~ 0x10
    }
    int blockSize = 16;

    // Act
    byte[] padded = ByteUtils.addPadding(input, blockSize);

    // Assert
    // paddingLength = 16 - (16 % 16) = 16 - 0 = 16
    // 결과: 원본 16 bytes + 패딩 16 bytes(값 0x10) = 32 bytes
    assertEquals(32, padded.length, "결과는 32바이트여야 한다");
    // 원본 데이터 보존 확인
    for (int i = 0; i < 16; i++) {
      assertEquals(input[i], padded[i], "원본 데이터 인덱스 " + i + "이 보존되어야 한다");
    }
    // 패딩 블록 확인
    for (int i = 16; i < 32; i++) {
      assertEquals(0x10, padded[i] & 0xFF,
          "패딩 바이트 인덱스 " + i + "의 값이 0x10(16)이어야 한다");
    }
  }

  @Test
  @DisplayName("입력 길이 == blockSize(16바이트): 패딩된 32바이트 removePadding → 원문 16바이트 복원")
  void removePadding_inputLengthEqualsBlockSize_restores16ByteOriginal() {
    // Arrange
    byte[] input = new byte[16];
    for (int i = 0; i < 16; i++) {
      input[i] = (byte) (i + 1);
    }
    int blockSize = 16;

    // Act
    byte[] padded = ByteUtils.addPadding(input, blockSize);
    byte[] restored = ByteUtils.removePadding(padded, blockSize);

    // Assert
    assertArrayEquals(input, restored, "원문 16바이트가 정확히 복원되어야 한다");
  }

  // ==================== 예외 경로: 조작된 패딩 ====================

  @Test
  @DisplayName("조작된 패딩: 마지막 바이트=0x03이지만 패딩 영역 값 불일치 → IllegalArgumentException('Invalid padding')")
  void removePadding_tamperedPaddingByteMismatch_throwsInvalidPaddingException() {
    // Arrange
    // 올바른 PKCS7 패딩(blockSize=16, paddingLength=3)이었다면:
    //   [..., 0x03, 0x03, 0x03]
    // 조작: 마지막에서 세 번째 바이트를 0x02로 변경
    //   [..., 0x02, 0x03, 0x03]
    int blockSize = 16;
    byte[] tampered = new byte[16];
    // 13바이트 데이터 영역은 임의값
    for (int i = 0; i < 13; i++) {
      tampered[i] = (byte) (i + 0x20);
    }
    tampered[13] = (byte) 0x02; // 조작된 바이트 — 0x03이어야 하는데 0x02로 변조
    tampered[14] = (byte) 0x03; // 패딩 (올바른 값)
    tampered[15] = (byte) 0x03; // 마지막 패딩 바이트 = paddingLength

    // Act & Assert
    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> ByteUtils.removePadding(tampered, blockSize),
        "조작된 패딩은 IllegalArgumentException을 발생시켜야 한다"
    );
    assertTrue(ex.getMessage().contains("Invalid padding"),
        "예외 메시지에 'Invalid padding'이 포함되어야 한다. 실제: " + ex.getMessage());
  }

  // ==================== 예외 경로: 패딩 마지막 바이트 0x00 ====================

  @Test
  @DisplayName("패딩 마지막 바이트 0x00: paddingLength < 1 조건 → IllegalArgumentException('Invalid padding length')")
  void removePadding_lastByteZero_throwsInvalidPaddingLengthException() {
    // Arrange
    // blockSize=16 배수인 16바이트 배열, 마지막 바이트를 0x00으로 설정
    int blockSize = 16;
    byte[] data = new byte[16];
    for (int i = 0; i < 15; i++) {
      data[i] = (byte) (i + 1);
    }
    data[15] = (byte) 0x00; // paddingLength = 0 → 유효하지 않음

    // Act & Assert
    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> ByteUtils.removePadding(data, blockSize),
        "마지막 바이트 0x00은 IllegalArgumentException을 발생시켜야 한다"
    );
    assertTrue(ex.getMessage().contains("Invalid padding length"),
        "예외 메시지에 'Invalid padding length'가 포함되어야 한다. 실제: " + ex.getMessage());
  }

  // ==================== 예외 경로: 패딩 마지막 바이트 값이 blockSize 초과 ====================

  @Test
  @DisplayName("패딩 마지막 바이트 0x11(17), blockSize=16: paddingLength > blockSize 조건 → IllegalArgumentException('Invalid padding length')")
  void removePadding_lastByteExceedsBlockSize_throwsInvalidPaddingLengthException() {
    // Arrange
    // blockSize=16 배수인 16바이트 배열, 마지막 바이트를 0x11(=17)로 설정
    // 17 > blockSize(16)이므로 유효하지 않은 패딩 길이
    int blockSize = 16;
    byte[] data = new byte[16];
    for (int i = 0; i < 15; i++) {
      data[i] = (byte) 0x11; // 임의 데이터
    }
    data[15] = (byte) 0x11; // paddingLength = 17 → blockSize(16) 초과

    // Act & Assert
    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> ByteUtils.removePadding(data, blockSize),
        "paddingLength > blockSize이면 IllegalArgumentException을 발생시켜야 한다"
    );
    assertTrue(ex.getMessage().contains("Invalid padding length"),
        "예외 메시지에 'Invalid padding length'가 포함되어야 한다. 실제: " + ex.getMessage());
  }
}
