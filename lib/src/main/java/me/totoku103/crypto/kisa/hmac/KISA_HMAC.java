package me.totoku103.crypto.kisa.hmac;

public class KISA_HMAC {

  // private static int ENDIAN = Common.BIG_ENDIAN;

  private static final byte IPAD = (byte) 0x36;
  private static final byte OPAD = (byte) 0x5C;
  private static final int blockLength = 64; // for SHA256
  private static final int digestLength = 32; // for SHA256

  public static void HMAC_SHA256_Transform(
      byte[] output, byte[] key, int keyLen, byte[] input, int inputLen) {
    byte[] keyPad = new byte[blockLength];

    // 1. Key Processing
    if (keyLen > blockLength) {
      SHA256_INFO info = new SHA256_INFO();
      KISA_SHA256.SHA256_Init(info);
      KISA_SHA256.SHA256_Process(info, key, keyLen);
      KISA_SHA256.SHA256_Close(info, keyPad);
    } else {
      System.arraycopy(key, 0, keyPad, 0, keyLen);
    }

    // 2. Inner and Outer Pads
    byte[] ipad = new byte[blockLength];
    byte[] opad = new byte[blockLength];
    for (int i = 0; i < blockLength; i++) {
      ipad[i] = (byte) (keyPad[i] ^ IPAD);
      opad[i] = (byte) (keyPad[i] ^ OPAD);
    }

    // 3. Inner Hash
    SHA256_INFO context = new SHA256_INFO();
    KISA_SHA256.SHA256_Init(context);
    KISA_SHA256.SHA256_Process(context, ipad, blockLength);
    KISA_SHA256.SHA256_Process(context, input, inputLen);
    byte[] firstHash = new byte[digestLength];
    KISA_SHA256.SHA256_Close(context, firstHash);

    // 4. Outer Hash
    KISA_SHA256.SHA256_Init(context);
    KISA_SHA256.SHA256_Process(context, opad, blockLength);
    KISA_SHA256.SHA256_Process(context, firstHash, digestLength);
    byte[] fullMac = new byte[digestLength];
    KISA_SHA256.SHA256_Close(context, fullMac);

    // 5. Truncate to desired length
    System.arraycopy(fullMac, 0, output, 0, output.length);
  }
}
