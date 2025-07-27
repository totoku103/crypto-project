package me.totoku103.crypto.kisa.aria;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.InvalidKeyException;
import me.totoku103.crypto.core.utils.ByteUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AriaCasesTest {

  @Test
  @DisplayName("128/192/256비트 키로 암호화 후 복호화하여 원문이 유지되는지 확인")
  void roundTripShouldWorkForDifferentKeySizes() throws InvalidKeyException {
    final String[][] vectors = {
      {"128", "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff"},
      {
        "192",
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "00112233445566778899aabbccddeeff"
      },
      {
        "256",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff"
      }
    };

    for (String[] v : vectors) {
      final int keySize = Integer.parseInt(v[0]);
      final byte[] key = ByteUtils.fromHexString(v[1]);
      final byte[] plain = ByteUtils.fromHexString(v[2]);

      final Aria aria = new Aria(keySize);
      aria.setKey(key);
      aria.setupRoundKeys();

      final byte[] enc = aria.encrypt(plain, 0);
      final byte[] dec = aria.decrypt(enc, 0);
      assertArrayEquals(plain, dec);
    }
  }

  @Test
  @DisplayName("지원하지 않는 키 길이를 사용하면 InvalidKeyException이 발생해야 한다")
  void invalidKeySizeShouldThrowException() {
    assertThrows(InvalidKeyException.class, () -> new Aria(100));
  }

  @Test
  @DisplayName("키를 설정하지 않고 암호화하면 InvalidKeyException이 발생해야 한다")
  void encryptWithoutKeyShouldThrowException() throws InvalidKeyException {
    final Aria aria = new Aria(128);
    final byte[] plain = new byte[16];
    final byte[] out = new byte[16];
    assertThrows(InvalidKeyException.class, () -> aria.encrypt(plain, 0, out, 0));
  }

  @Test
  @DisplayName("키 길이가 부족할 때 setKey가 InvalidKeyException을 발생해야 한다")
  void shortKeyShouldThrowException() throws InvalidKeyException {
    final Aria aria = new Aria(256);
    final byte[] shortKey = new byte[16];
    assertThrows(InvalidKeyException.class, () -> aria.setKey(shortKey));
  }

  @Test
  @DisplayName("reset 호출 후 다른 키 길이를 설정해도 정상적으로 동작해야 한다")
  void shouldReuseAfterReset() throws InvalidKeyException {
    final Aria aria = new Aria(128);
    final byte[] key1 = ByteUtils.fromHexString("000102030405060708090a0b0c0d0e0f");
    final byte[] plain = ByteUtils.fromHexString("00112233445566778899aabbccddeeff");
    aria.setKey(key1);
    aria.setupRoundKeys();
    final byte[] enc1 = aria.encrypt(plain, 0);
    assertArrayEquals(plain, aria.decrypt(enc1, 0));

    aria.reset();
    aria.setKeySize(192);
    final byte[] key2 = ByteUtils.fromHexString("000102030405060708090a0b0c0d0e0f1011121314151617");
    aria.setKey(key2);
    aria.setupRoundKeys();
    final byte[] enc2 = aria.encrypt(plain, 0);
    assertArrayEquals(plain, aria.decrypt(enc2, 0));
  }
}
