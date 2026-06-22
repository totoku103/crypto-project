package me.totoku103.crypto.password;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * BCryptPasswordEncoder 동시성 안전성 테스트.
 *
 * <p>cost=4로 고정하여 CI 환경에서 타임아웃 없이 실행된다.
 */
@DisplayName("BCryptPasswordEncoder 동시성 안전성")
class BCryptPasswordEncoderConcurrencyTest {

  /** CI 타임아웃 방지를 위해 cost=4 고정 */
  private static final int COST = 4;

  /** 스레드 수 */
  private static final int THREAD_COUNT = 8;

  /** 총 encode 호출 횟수 (8 스레드 × 100회) */
  private static final int TOTAL_ENCODE_COUNT = 800;

  /** 각 스레드당 encode 호출 횟수 */
  private static final int CALLS_PER_THREAD = TOTAL_ENCODE_COUNT / THREAD_COUNT;

  /** 테스트용 원문 패스워드 */
  private static final String RAW_PASSWORD = "P@ssw0rd!동시성테스트";

  @Test
  @DisplayName("8 스레드가 encode()를 동시에 100회씩 호출해도 예외 없이 완료된다")
  void concurrent_encode_noException() throws InterruptedException {
    // Arrange
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(COST);
    ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
    CountDownLatch startLatch = new CountDownLatch(1);
    AtomicInteger errorCount = new AtomicInteger(0);
    List<Future<Void>> futures = new ArrayList<>();

    // Act: 8 스레드 동시 출발
    for (int t = 0; t < THREAD_COUNT; t++) {
      Future<Void> future = executor.submit(new Callable<Void>() {
        @Override
        public Void call() throws Exception {
          startLatch.await();
          for (int i = 0; i < CALLS_PER_THREAD; i++) {
            try {
              encoder.encode(RAW_PASSWORD);
            } catch (Exception e) {
              errorCount.incrementAndGet();
            }
          }
          return null;
        }
      });
      futures.add(future);
    }

    startLatch.countDown(); // 모든 스레드 동시 출발

    // 모든 future 완료 대기 (최대 120초)
    executor.shutdown();
    boolean finished = executor.awaitTermination(120, TimeUnit.SECONDS);

    // Assert
    assertTrue(finished, "모든 스레드가 120초 내에 완료되어야 함");
    assertEquals(0, errorCount.get(), "동시 encode() 호출 중 예외가 발생하지 않아야 함");

    // future에서 발생한 예외도 확인
    for (Future<Void> future : futures) {
      assertDoesNotThrow(() -> future.get(), "스레드 실행 중 예외가 없어야 함");
    }
  }

  @Test
  @DisplayName("동시 encode() 800개 결과 모두 isBCryptHash()를 통과하며 60자 표준 포맷이다")
  void concurrent_encode_allResultsAreBcryptFormat() throws InterruptedException, ExecutionException {
    // Arrange
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(COST);
    ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
    CountDownLatch startLatch = new CountDownLatch(1);
    List<String> results = Collections.synchronizedList(new ArrayList<String>());
    List<Future<Void>> futures = new ArrayList<>();

    // Act
    for (int t = 0; t < THREAD_COUNT; t++) {
      Future<Void> future = executor.submit(new Callable<Void>() {
        @Override
        public Void call() throws Exception {
          startLatch.await();
          for (int i = 0; i < CALLS_PER_THREAD; i++) {
            results.add(encoder.encode(RAW_PASSWORD));
          }
          return null;
        }
      });
      futures.add(future);
    }

    startLatch.countDown();
    executor.shutdown();
    executor.awaitTermination(120, TimeUnit.SECONDS);

    // future 예외 전파
    for (Future<Void> future : futures) {
      future.get();
    }

    // Assert
    assertEquals(TOTAL_ENCODE_COUNT, results.size(),
        "encode() 호출 수(" + TOTAL_ENCODE_COUNT + ")와 결과 수가 일치해야 함");

    for (String hash : results) {
      // 60자 표준 포맷 확인
      assertEquals(60, hash.length(),
          "bcrypt 해시는 60자여야 함: " + hash);
      // isBCryptHash() 포맷 검증
      assertTrue(BCryptPasswordEncoder.isBCryptHash(hash),
          "isBCryptHash()를 통과해야 함: " + hash);
      // cost 필드 확인
      assertTrue(hash.startsWith("$2y$04$"),
          "cost=4 해시는 $2y$04$로 시작해야 함: " + hash);
    }
  }

  @Test
  @DisplayName("동시 encode() 결과에서 salt 부분(7~28번째 문자) 집합 크기가 800이다 — salt 독립성 결정론적 검증")
  void concurrent_encode_saltSetSizeEquals800() throws InterruptedException, ExecutionException {
    // Arrange
    // bcrypt 해시 포맷: $2y$04$<22자 salt><31자 hash> = 60자
    // 인덱스: $2y$04$ = 7자 → salt는 index 7~28 (22자)
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(COST);
    ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
    CountDownLatch startLatch = new CountDownLatch(1);
    List<String> results = Collections.synchronizedList(new ArrayList<String>());
    List<Future<Void>> futures = new ArrayList<>();

    // Act
    for (int t = 0; t < THREAD_COUNT; t++) {
      Future<Void> future = executor.submit(new Callable<Void>() {
        @Override
        public Void call() throws Exception {
          startLatch.await();
          for (int i = 0; i < CALLS_PER_THREAD; i++) {
            results.add(encoder.encode(RAW_PASSWORD));
          }
          return null;
        }
      });
      futures.add(future);
    }

    startLatch.countDown();
    executor.shutdown();
    executor.awaitTermination(120, TimeUnit.SECONDS);

    for (Future<Void> future : futures) {
      future.get();
    }

    // Assert: salt 필드(index 7~28, 22자) 집합 크기가 800이어야 한다
    // bcrypt는 호출마다 독립적인 16바이트 SecureRandom salt를 생성하므로
    // 이론적 충돌 확률은 2^-128 수준으로 무시 가능하다
    Set<String> saltSet = new HashSet<>();
    for (String hash : results) {
      // $2y$04$ → 7자, 이후 22자가 base64 인코딩된 salt
      String saltPart = hash.substring(7, 29);
      saltSet.add(saltPart);
    }

    assertEquals(TOTAL_ENCODE_COUNT, saltSet.size(),
        "800회 encode() 호출 결과의 salt 필드가 모두 고유해야 함 (SecureRandom 독립성)");
  }

  @Test
  @DisplayName("4 스레드 encode() + 4 스레드 matches()를 동시에 실행해도 matches() 결과가 올바르다")
  void concurrent_encodeAndMatches_correctResult() throws InterruptedException, ExecutionException {
    // Arrange
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(COST);

    // matches() 검증을 위해 사전에 해시 100개 생성
    final int MATCH_COUNT = 100;
    final String MATCH_PASSWORD = "matchTestPassword!";
    final String WRONG_PASSWORD = "wrongPassword!";

    List<String> preEncodedHashes = new ArrayList<>();
    for (int i = 0; i < MATCH_COUNT; i++) {
      preEncodedHashes.add(encoder.encode(MATCH_PASSWORD));
    }

    ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
    CountDownLatch startLatch = new CountDownLatch(1);
    List<Future<Void>> futures = new ArrayList<>();

    // encode 스레드 4개
    for (int t = 0; t < 4; t++) {
      Future<Void> future = executor.submit(new Callable<Void>() {
        @Override
        public Void call() throws Exception {
          startLatch.await();
          for (int i = 0; i < CALLS_PER_THREAD; i++) {
            encoder.encode(RAW_PASSWORD);
          }
          return null;
        }
      });
      futures.add(future);
    }

    // matches 스레드 4개: 올바른 패스워드는 true, 잘못된 패스워드는 false여야 함
    List<Boolean> correctResults = Collections.synchronizedList(new ArrayList<Boolean>());
    List<Boolean> wrongResults = Collections.synchronizedList(new ArrayList<Boolean>());

    for (int t = 0; t < 4; t++) {
      final int threadIdx = t;
      Future<Void> future = executor.submit(new Callable<Void>() {
        @Override
        public Void call() throws Exception {
          startLatch.await();
          // 각 matches 스레드가 MATCH_COUNT / 4개씩 담당
          int perThread = MATCH_COUNT / 4;
          int start = threadIdx * perThread;
          int end = start + perThread;
          for (int i = start; i < end; i++) {
            String hash = preEncodedHashes.get(i);
            correctResults.add(encoder.matches(MATCH_PASSWORD, hash));
            wrongResults.add(encoder.matches(WRONG_PASSWORD, hash));
          }
          return null;
        }
      });
      futures.add(future);
    }

    // Act
    startLatch.countDown();
    executor.shutdown();
    executor.awaitTermination(120, TimeUnit.SECONDS);

    for (Future<Void> future : futures) {
      future.get();
    }

    // Assert
    assertEquals(MATCH_COUNT, correctResults.size(),
        "matches() 결과 수가 입력 해시 수와 같아야 함");
    assertEquals(MATCH_COUNT, wrongResults.size(),
        "잘못된 패스워드 matches() 결과 수가 입력 해시 수와 같아야 함");

    // 올바른 패스워드는 모두 true
    for (int i = 0; i < correctResults.size(); i++) {
      assertTrue(correctResults.get(i),
          "올바른 패스워드는 matches()가 true여야 함 (index=" + i + ")");
    }

    // 잘못된 패스워드는 모두 false
    for (int i = 0; i < wrongResults.size(); i++) {
      assertFalse(wrongResults.get(i),
          "잘못된 패스워드는 matches()가 false여야 함 (index=" + i + ")");
    }
  }
}
