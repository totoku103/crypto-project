package me.totoku103.crypto.kisa.hmac;

public class Utils {

  private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

  public static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] =
          (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
    }
    return data;
  }

  public static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  public static int asc2hex(byte[] dst, String src) {
    byte temp = 0x00, hex = 0;
    int i = 0;

    for (i = 0; i < src.length(); i++) {
      temp = 0x00;
      hex = (byte) src.charAt(i);

      if ((hex >= 0x30) && (hex <= 0x39)) temp = (byte) (hex - 0x30);
      else if ((hex >= 0x41) && (hex <= 0x5A)) temp = (byte) (hex - 0x41 + 10);
      else if ((hex >= 0x61) && (hex <= 0x7A)) temp = (byte) (hex - 0x61 + 10);
      else temp = 0x00;

      if ((i & 1) == 1) dst[i >> 1] ^= temp & 0x0F;
      else dst[i >> 1] = (byte) (temp << 4);
    }

    return ((i + 1) / 2);
  }

  public static void print_hex(String valName, byte[] data, int dataLen) {
    int i = 0;

    System.out.printf("%s [%dbyte] :", valName, dataLen);
    for (i = 0; i < dataLen; i++) {
      if ((i & 0x0F) == 0) System.out.println("");

      System.out.printf(" %02X", data[i]);
    }
    System.out.println("");
  }

  public static void print_title(String title) {
    System.out.println("================================================");
    System.out.println("  " + title);
    System.out.println("================================================");
  }

  public static void print_result(String func, int ret) {
    if (ret == 1) {
      System.out.println("================================================");
      System.out.println("  " + func + " Failure!");
      System.out.println("================================================");

      System.exit(0);
    } else {
      System.out.println("================================================");
      System.out.println("  " + func + " Success!");
      System.out.println("================================================");
    }
  }

  public static void word2byte(byte[] dst, int pos, int src, int srcLen) {
    int cnt_i = 0, shift = 0;
    for (cnt_i = 0; cnt_i < srcLen; cnt_i++) {
      shift = (srcLen - (cnt_i + 1)) * 8;
      dst[pos + cnt_i] = (byte) ((src >> shift) & 0xff);
    }
  }
}
