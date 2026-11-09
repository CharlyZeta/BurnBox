package com.burnbox.ratelimit;

import java.time.Duration;

public enum BucketType {
    REVEAL_IP(20, Duration.ofMinutes(1)),
    REVEAL_TOKEN(10, Duration.ofMinutes(1)),
    CREATE_IP(30, Duration.ofHours(1));

    private final long capacity;
    private final Duration refillPeriod;

    BucketType(long capacity, Duration refillPeriod) {
        this.capacity = capacity;
        this.refillPeriod = refillPeriod;
    }

    public long getCapacity() {
        return capacity;
    }

    public Duration getRefillPeriod() {
        return refillPeriod;
    }
}
