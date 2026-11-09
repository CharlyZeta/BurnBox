package com.burnbox.ratelimit;

import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe rate limiter driven strictly by the injected {@link Clock}.
 * Implements token bucket algorithm for REVEAL_IP, REVEAL_TOKEN, and CREATE_IP.
 */
@Component
public class RateLimiter {

    private final Clock clock;
    private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    public RateLimiter(Clock clock) {
        this.clock = clock;
    }

    public RateLimitResult tryConsume(String key, BucketType type) {
        String bucketKey = type.name() + ":" + key;
        TokenBucket bucket = buckets.computeIfAbsent(bucketKey, _k -> new TokenBucket(type.getCapacity(), type.getRefillPeriod(), clock.instant()));
        return bucket.tryConsume(clock.instant());
    }

    public void reset() {
        buckets.clear();
    }

    private static class TokenBucket {
        private final long capacity;
        private final long refillPeriodNanos;
        private double tokens;
        private Instant lastRefill;

        TokenBucket(long capacity, Duration refillPeriod, Instant now) {
            this.capacity = capacity;
            this.refillPeriodNanos = refillPeriod.toNanos();
            this.tokens = capacity;
            this.lastRefill = now;
        }

        synchronized RateLimitResult tryConsume(Instant now) {
            refill(now);
            if (tokens >= 1.0) {
                tokens -= 1.0;
                return new RateLimitResult.Allowed((long) tokens);
            } else {
                double needed = 1.0 - tokens;
                long nanosUntilToken = (long) Math.ceil((needed * refillPeriodNanos) / capacity);
                long seconds = (nanosUntilToken + 999_999_999L) / 1_000_000_000L;
                long retryAfter = Math.max(1, seconds);
                return new RateLimitResult.Denied(retryAfter);
            }
        }

        private void refill(Instant now) {
            if (now.isBefore(lastRefill)) {
                return;
            }
            long elapsedNanos = Duration.between(lastRefill, now).toNanos();
            if (elapsedNanos <= 0) {
                return;
            }
            double generated = ((double) elapsedNanos * capacity) / refillPeriodNanos;
            tokens = Math.min(capacity, tokens + generated);
            lastRefill = now;
        }
    }
}
