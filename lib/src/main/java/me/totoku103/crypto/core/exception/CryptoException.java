package me.totoku103.crypto.core.exception;

/** 암호화 관련 예외 클래스 */
public class CryptoException extends RuntimeException {

  public CryptoException(String message) {
    super(message);
  }

  public CryptoException(String message, Throwable cause) {
    super(message, cause);
  }

  public CryptoException(Throwable cause) {
    super(cause);
  }
}
