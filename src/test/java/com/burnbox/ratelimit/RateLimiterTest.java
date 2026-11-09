package com.burnbox.ratelimit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class RateLimiterTest {

    private static final Instant BASE_TIME = Instant.parse("2026-11-09T12:00:00Z");

    @Test
    @DisplayName("BR-001 & BR-002: Bucket limits configured and Retry-After calculated")
    void bucketLimitsConfigured() {
        MutableTestClock clock = new MutableTestClock(BASE_TIME);
        RateLimiter limiter = new RateLimiter(clock);

        // REVEAL_IP: capacity is 20 per minute
        for (int i = 0; i < 20; i++) {
            RateLimitResult result = limiter.tryConsume("192.168.1.0/24", BucketType.REVEAL_IP);
            assertTrue(result.isAllowed(), "Request " + (i + 1) + " should be allowed");
        }

        // 21st request should be rejected
        RateLimitResult blocked = limiter.tryConsume("192.168.1.0/24", BucketType.REVEAL_IP);
        assertFalse(blocked.isAllowed());
        assertInstanceOf(RateLimitResult.Denied.class, blocked);
        RateLimitResult.Denied denied = (RateLimitResult.Denied) blocked;
        assertTrue(denied.retryAfterSeconds() >= 1, "Retry-After should be at least 1 second");
    }

    @Test
    @DisplayName("BR-002: Retry-After format is positive integer")
    void retryAfterHeaderFormattedCorrectly() {
        MutableTestClock clock = new MutableTestClock(BASE_TIME);
        RateLimiter limiter = new RateLimiter(clock);

        // Exhaust REVEAL_TOKEN (capacity 10)
        for (int i = 0; i < 10; i++) {
            limiter.tryConsume("sample-token-hash", BucketType.REVEAL_TOKEN);
        }

        RateLimitResult result = limiter.tryConsume("sample-token-hash", BucketType.REVEAL_TOKEN);
        assertFalse(result.isAllowed());
        assertInstanceOf(RateLimitResult.Denied.class, result);
        long retryAfter = ((RateLimitResult.Denied) result).retryAfterSeconds();
        assertTrue(retryAfter > 0 && retryAfter <= 60);
    }

    @Test
    @DisplayName("BR-006: Injected clock controls token refill without sleeping")
    void clockInjectedDrivesRefillAndExpiry() {
        MutableTestClock clock = new MutableTestClock(BASE_TIME);
        RateLimiter limiter = new RateLimiter(clock);

        // Exhaust CREATE_IP (30 per hour)
        for (int i = 0; i < 30; i++) {
            assertTrue(limiter.tryConsume("10.0.0.0/24", BucketType.CREATE_IP).isAllowed());
        }
        assertFalse(limiter.tryConsume("10.0.0.0/24", BucketType.CREATE_IP).isAllowed());

        // Advance clock by 30 minutes (refills half capacity ~ 15 tokens)
        clock.advance(Duration.ofMinutes(30));

        RateLimitResult refilledResult = limiter.tryConsume("10.0.0.0/24", BucketType.CREATE_IP);
        assertTrue(refilledResult.isAllowed(), "Should be allowed after clock advancement");
    }

    static class MutableTestClock extends Clock {
        private final AtomicReference<Instant> current;
        private final ZoneOffset zone = ZoneOffset.UTC;

        MutableTestClock(Instant initial) {
            this.current = new AtomicReference<>(initial);
        }

        void advance(Duration duration) {
            current.updateAndGet(i -> i.plus(duration));
        }

        @Override
        public ZoneOffset getZone() {
            return zone;
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
