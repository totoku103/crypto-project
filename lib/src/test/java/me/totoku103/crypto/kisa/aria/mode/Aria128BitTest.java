package me.totoku103.crypto.kisa.aria.mode;

import java.security.InvalidKeyException;
import me.totoku103.crypto.kisa.aria.SimpleAria;
import me.totoku103.crypto.core.utils.ByteUtils;
import org.junit.jupiter.api.Test;

public class Aria128BitTest {

  private final String encryptKey = TestVector.EncryptKey.BIT_128_KEY.getKeyHex();

  @Test
  public void ecb() throws InvalidKeyException {
    final SimpleAria aria = new SimpleAria(128, encryptKey);
    final String s = aria.encryptEcb("askas dfkljsadlkfjsad fklj");
    System.out.println(s);
    final String s1 = aria.decryptEcb(s);
    System.out.println(s1);
  }

  @Test
  public void test() {
    final String hex = "11111111aaaaaaaa11111111bbbbbbbb";
    final byte[] bytes = ByteUtils.fromHexString(hex);
    System.out.println(new String(bytes));
  }
}
