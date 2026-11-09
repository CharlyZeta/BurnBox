package com.burnbox.ratelimit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AbuseDetectorTest {

    private static final Instant BASE_TIME = Instant.parse("2026-11-09T12:00:00Z");

    @Test
    @DisplayName("BR-004: 10 failed attempts with distinct tokens in 5 minutes triggers 1 hour block")
    void tenFailedTokensTriggersOneHourBlock() {
        MutableTestClock clock = new MutableTestClock(BASE_TIME);
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        AbuseDetector detector = new AbuseDetector(clock, publisher);

        String ipPrefix = "192.0.2.0/24";

        // 9 failed attempts should not trigger block
        for (int i = 1; i <= 9; i++) {
            detector.recordFailedTokenAttempt(ipPrefix, "token-hash-" + i);
            assertFalse(detector.isBlocked(ipPrefix), "Should not be blocked at attempt " + i);
        }

        // 10th distinct token triggers block
        detector.recordFailedTokenAttempt(ipPrefix, "token-hash-10");
        assertTrue(detector.isBlocked(ipPrefix), "10th attempt should trigger block");
        assertTrue(detector.getBlockRemainingSeconds(ipPrefix) > 3500, "Remaining seconds should be ~3600");

        // Advance 30 minutes -> still blocked
        clock.advance(Duration.ofMinutes(30));
        assertTrue(detector.isBlocked(ipPrefix));

        // Advance 31 minutes (total 61 min) -> unblocked
        clock.advance(Duration.ofMinutes(31));
        assertFalse(detector.isBlocked(ipPrefix));
    }

    @Test
    @DisplayName("BR-005: AbuseIpFlagged event emitted with prefix and timestamp without plaintext secrets")
    void abuseIpFlaggedEventEmittedWithoutPii() {
        MutableTestClock clock = new MutableTestClock(BASE_TIME);
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        AbuseDetector detector = new AbuseDetector(clock, publisher);

        String ipPrefix = "203.0.113.0/24";

        for (int i = 1; i <= 10; i++) {
            detector.recordFailedTokenAttempt(ipPrefix, "hash-" + i);
        }

        ArgumentCaptor<AbuseIpFlagged> captor = ArgumentCaptor.forClass(AbuseIpFlagged.class);
        verify(publisher, times(1)).publishEvent(captor.capture());

        AbuseIpFlagged event = captor.getValue();
        assertEquals(ipPrefix, event.ipPrefix());
        assertEquals(BASE_TIME, event.flaggedAt());
        assertNotNull(event.reason());
        assertFalse(event.reason().contains("hash-"), "Reason should not contain raw token hashes");
    }

    static class MutableTestClock extends Clock {
        private final AtomicReference<Instant> current;

        MutableTestClock(Instant initial) {
            this.current = new AtomicReference<>(initial);
        }

        void advance(Duration duration) {
            current.updateAndGet(i -> i.plus(duration));
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return current.get();
        }
    }
}
