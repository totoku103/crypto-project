# Sha256MessageDigest와 Sha256Vanilla 비교

두 구현은 모두 SHA-256 해시 값을 계산하지만 방식이 다릅니다.

* `Sha256Vanilla`는 KISA에서 제공한 레퍼런스 코드를 그대로 옮긴 순수 자바 구현입니다. 내부적으로 상태를 관리하며 직접 라운드를 수행합니다.
* `Sha256MessageDigest`는 JDK의 `MessageDigest` 클래스를 사용합니다. JDK가 제공하는 최적화된 구현을 그대로 활용하므로 코드가 간단하며 성능이 좋습니다.
* 두 클래스 모두 동일한 바이트 배열을 반환한다. 하지만 `Sha256Vanilla.encrypt(byte[])` 메서드는 각 바이트를 패딩 없이 16진수 문자열로 변환하기 때문에 길이가 변동될 수 있다. 이에 비해 `Sha256MessageDigest.encrypt(byte[])`는 두 자리로 패딩해 64자리 16진수 문자열을 반환한다.
