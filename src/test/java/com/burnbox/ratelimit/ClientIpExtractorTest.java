package com.burnbox.ratelimit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ClientIpExtractorTest {

    @Test
    @DisplayName("BR-003: Subnet /24 grouping for IPv4 addresses and /64 for IPv6")
    void ipV4AndV6PrefixNormalization() {
        ClientIpExtractor extractor = new ClientIpExtractor();

        // IPv4 /24 normalization
        assertEquals("192.168.1.0/24", extractor.normalizeToPrefix("192.168.1.100"));
        assertEquals("192.168.1.0/24", extractor.normalizeToPrefix("192.168.1.254"));
        assertEquals("10.0.5.0/24", extractor.normalizeToPrefix("10.0.5.12"));

        // IPv6 /64 normalization
        assertEquals("2001:db8:abcd:12::/64", extractor.normalizeToPrefix("2001:0db8:abcd:0012:0000:0000:0000:0001"));
        assertEquals("fe80:0:0:0::/64", extractor.normalizeToPrefix("fe80::1:2:3:4"));
    }

    @Test
    @DisplayName("AF-04: X-Forwarded-For is honored only from trusted proxies")
    void trustedProxyIpExtraction() {
        ClientIpExtractor extractor = new ClientIpExtractor(Set.of("127.0.0.1", "10.0.0.1"));

        // From trusted proxy -> read forwarded client IP
        MockHttpServletRequest req1 = new MockHttpServletRequest();
        req1.setRemoteAddr("127.0.0.1");
        req1.addHeader("X-Forwarded-For", "203.0.113.195, 10.0.0.1");
        assertEquals("203.0.113.195", extractor.extractClientIp(req1));

        // From untrusted proxy -> ignore header and use remote address
        MockHttpServletRequest req2 = new MockHttpServletRequest();
        req2.setRemoteAddr("198.51.100.44");
        req2.addHeader("X-Forwarded-For", "203.0.113.195");
        assertEquals("198.51.100.44", extractor.extractClientIp(req2));
    }
}
