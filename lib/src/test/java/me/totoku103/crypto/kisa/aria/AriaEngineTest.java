package me.totoku103.crypto.kisa.aria;

import me.totoku103.crypto.core.utils.ByteUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class AriaEngineTest {

  @Test
  @DisplayName("새로운 ARIA 엔진 구현이 기존 구현과 동일한 결과를 생성하는지 검증")
  public void engineShouldMatchReferenceImplementation() throws InvalidKeyException {
    final byte[] key =
        ByteUtils.fromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    final byte[] plain = ByteUtils.fromHexString("00112233445566778899aabbccddeeff");

    final Aria original = new Aria(256);
    original.setKey(key);
    original.setupRoundKeys();
    final byte[] expected = original.encrypt(plain, 0);

    final Aria engine = new Aria(256);
    engine.setKey(key);
    engine.setupRoundKeys();
    final byte[] actual = engine.encrypt(plain, 0);

    assertArrayEquals(expected, actual);
    assertArrayEquals(plain, engine.decrypt(actual, 0));
  }
}
