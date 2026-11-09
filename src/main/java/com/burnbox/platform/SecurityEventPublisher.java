package com.burnbox.platform;

import java.util.Map;

/**
 * Port for publishing security events across module boundaries.
 */
public interface SecurityEventPublisher {

    void publish(String eventType, Map<String, Object> details);

    void publish(String eventType, String subjectType, String subjectId, Map<String, Object> details);
}
