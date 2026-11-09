package com.burnbox.ratelimit;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Monitors repeated failed token attempts by IP prefix.
 * If 10 or more distinct failed tokens occur from the same prefix within a 5-minute sliding window,
 * an abuse block of 1 hour is placed on the prefix and {@link AbuseIpFlagged} is published.
 */
@Component
public class AbuseDetector {

    private static final int FAILURE_THRESHOLD = 10;
    private static final Duration WINDOW_DURATION = Duration.ofMinutes(5);
    private static final Duration BLOCK_DURATION = Duration.ofHours(1);

    private final Clock clock;
    private final ApplicationEventPublisher eventPublisher;

    private final ConcurrentHashMap<String, IpAbuseState> ipStates = new ConcurrentHashMap<>();

    public AbuseDetector(Clock clock, ApplicationEventPublisher eventPublisher) {
        this.clock = clock;
        this.eventPublisher = eventPublisher;
    }

    public boolean isBlocked(String ipPrefix) {
        IpAbuseState state = ipStates.get(ipPrefix);
        if (state == null) {
            return false;
        }
        return state.isBlocked(clock.instant());
    }

    public long getBlockRemainingSeconds(String ipPrefix) {
        IpAbuseState state = ipStates.get(ipPrefix);
        if (state == null) {
            return 0;
        }
        return state.getBlockRemainingSeconds(clock.instant());
    }

    public void recordFailedTokenAttempt(String ipPrefix, String tokenHash) {
        IpAbuseState state = ipStates.computeIfAbsent(ipPrefix, _k -> new IpAbuseState());
        Instant now = clock.instant();
        boolean newlyBlocked = state.recordFailure(tokenHash, now);
        if (newlyBlocked) {
            eventPublisher.publishEvent(new AbuseIpFlagged(
                    ipPrefix,
                    now,
                    "Detected 10 distinct failed tokens within 5 minutes"
            ));
        }
    }

    public void reset() {
        ipStates.clear();
    }

    private static class IpAbuseState {
        private Instant blockUntil = null;
        private final Map<String, Instant> failedTokenHashes = new ConcurrentHashMap<>();

        synchronized boolean isBlocked(Instant now) {
            if (blockUntil == null) {
                return false;
            }
            if (now.isBefore(blockUntil)) {
                return true;
            }
            blockUntil = null;
            return false;
        }

        synchronized long getBlockRemainingSeconds(Instant now) {
            if (blockUntil == null || !now.isBefore(blockUntil)) {
                return 0;
            }
            long seconds = Duration.between(now, blockUntil).toSeconds();
            return Math.max(1, seconds);
        }

        synchronized boolean recordFailure(String tokenHash, Instant now) {
            if (isBlocked(now)) {
                return false;
            }

            // Purge attempts older than sliding window
            Instant cutoff = now.minus(WINDOW_DURATION);
            failedTokenHashes.entrySet().removeIf(entry -> entry.getValue().isBefore(cutoff));

            failedTokenHashes.put(tokenHash, now);

            if (failedTokenHashes.size() >= FAILURE_THRESHOLD) {
                blockUntil = now.plus(BLOCK_DURATION);
                failedTokenHashes.clear();
                return true;
            }
            return false;
        }
    }
}
