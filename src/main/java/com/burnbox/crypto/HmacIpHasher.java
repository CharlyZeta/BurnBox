package com.burnbox.crypto;

import com.burnbox.platform.IpHasher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Computes non-reversible HMAC-SHA256 hash of IP addresses using a configurable salt.
 * Resides exclusively in the crypto module to encapsulate javax.crypto.
 */
@Component
public class HmacIpHasher implements IpHasher {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private final byte[] saltBytes;

    public HmacIpHasher(@Value("${burnbox.security.ip-hash-salt:burnbox-default-ip-hash-salt-for-dev}") String salt) {
        if (salt == null || salt.isBlank()) {
            throw new IllegalArgumentException("IP hash salt cannot be null or blank");
        }
        this.saltBytes = salt.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String hashIp(String clientIp) {
        String ipToHash = (clientIp == null || clientIp.isBlank()) ? "0.0.0.0" : clientIp.trim();
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec secretKey = new SecretKeySpec(saltBytes, HMAC_ALGORITHM);
            mac.init(secretKey);
            byte[] hmacBytes = mac.doFinal(ipToHash.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hmacBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new CryptoException("Failed to compute IP HMAC", e);
        }
    }
}
