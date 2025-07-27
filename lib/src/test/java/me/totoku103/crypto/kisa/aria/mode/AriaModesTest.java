package me.totoku103.crypto.kisa.aria.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import me.totoku103.crypto.core.utils.ByteUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AriaModesTest {
  private static final byte[] KEY =
      ByteUtils.fromHexString("00112233445566778899aabbccddeeff0011223344556677");
  private static final byte[] IV = ByteUtils.fromHexString("0f1e2d3c4b5a69788796a5b4");
  private static final byte[] AAD = "header".getBytes();

  @Test
  @DisplayName("CTR 모드에서 암복호화 시 원문이 동일하게 복원되어야 한다")
  void ctrModeShouldRoundTrip() {
    byte[] data = "hello aria ctr".getBytes();
    byte[] enc = AriaModes.processCtr(KEY, IV, data);
    byte[] dec = AriaModes.processCtr(KEY, IV, enc);
    assertArrayEquals(data, dec);
  }

  @Test
  @DisplayName("CFB 모드에서 암복호화 시 원문이 동일하게 복원되어야 한다")
  void cfbModeShouldRoundTrip() {
    byte[] data = "hello aria cfb".getBytes();
    byte[] enc = AriaModes.encryptCfb(KEY, IV, data);
    byte[] dec = AriaModes.decryptCfb(KEY, IV, enc);
    assertArrayEquals(data, dec);
  }

  @Test
  @DisplayName("OFB 모드에서 암복호화 시 원문이 동일하게 복원되어야 한다")
  void ofbModeShouldRoundTrip() {
    byte[] data = "hello aria ofb".getBytes();
    byte[] enc = AriaModes.processOfb(KEY, IV, data);
    byte[] dec = AriaModes.processOfb(KEY, IV, enc);
    assertArrayEquals(data, dec);
  }

  @Test
  @DisplayName("GCM 모드 암복호화를 수행하여 태그와 함께 원문이 복원되는지 검증")
  void gcmModeShouldRoundTrip() throws InvalidCipherTextException {
    byte[] data = "gcm test data".getBytes();
    AriaModes.AeadResult res = AriaModes.encryptGcm(KEY, IV, AAD, data, 128);
    byte[] plain = AriaModes.decryptGcm(KEY, IV, AAD, res.ciphertext, res.tag);
    assertArrayEquals(data, plain);
  }

  @Test
  @DisplayName("CCM 모드 암복호화를 수행하여 태그와 함께 원문이 복원되는지 검증")
  void ccmModeShouldRoundTrip() throws InvalidCipherTextException {
    byte[] data = "ccm test data".getBytes();
    AriaModes.AeadResult res = AriaModes.encryptCcm(KEY, IV, AAD, data, 128);
    byte[] plain = AriaModes.decryptCcm(KEY, IV, AAD, res.ciphertext, res.tag);
    assertArrayEquals(data, plain);
  }

  @Test
  @DisplayName("같은 입력에 대한 CMAC 계산 결과가 항상 동일해야 한다")
  void cmacShouldBeDeterministic() {
    byte[] data = "message".getBytes();
    byte[] mac1 = AriaModes.cmac(KEY, data);
    byte[] mac2 = AriaModes.cmac(KEY, data);
    assertArrayEquals(mac1, mac2);
  }
}
