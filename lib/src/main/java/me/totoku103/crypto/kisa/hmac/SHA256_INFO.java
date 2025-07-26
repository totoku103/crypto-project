package me.totoku103.crypto.kisa.hmac;

public class SHA256_INFO {
  public int uChainVar[] = new int[KISA_SHA256.SHA256_DIGEST_VALUELEN / 4];
  public int uHighLength;
  public int uLowLength;
  public byte szBuffer[] = new byte[KISA_SHA256.SHA256_DIGEST_BLOCKLEN];
}
