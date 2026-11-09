package com.burnbox.platform;

/**
 * Interface for computing non-reversible salted IP hashes for audit and rate-limiting.
 * Keeps javax.crypto decoupled from the platform module.
 */
public interface IpHasher {
    String hashIp(String clientIp);
}
