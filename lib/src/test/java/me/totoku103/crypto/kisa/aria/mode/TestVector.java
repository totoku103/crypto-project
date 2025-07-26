package me.totoku103.crypto.kisa.aria.mode;

public enum TestVector {
  None;

  public enum EncryptKey {
    BIT_128_KEY("00112233445566778899aabbccddeeff"),
    BIT_192_KEY("00112233445566778899aabbccddeeff0011223344556677"),
    BIT_256_KEY("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

    private final String keyHex;

    EncryptKey(String keyHex) {
      this.keyHex = keyHex;
    }

    public String getKeyHex() {
      return keyHex;
    }
  }

  public enum IV {
    DEFAULT_128_IV("0f1e2d3c4b5a69788796a5b4c3d2e1f0");

    private final String ivHex;

    IV(String ivHex) {
      this.ivHex = ivHex;
    }

    public String getIvHex() {
      return ivHex;
    }
  }
}
