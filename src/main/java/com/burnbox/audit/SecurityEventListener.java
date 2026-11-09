package com.burnbox.audit;

import com.burnbox.platform.SecurityEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Listener that consumes domain SecurityEvents and delegates to audit persistence.
 */
@Component
public class SecurityEventListener {

    private final SecurityEventRepository repository;

    public SecurityEventListener(SecurityEventRepository repository) {
        this.repository = repository;
    }

    @EventListener
    public void onSecurityEvent(SecurityEvent event) {
        repository.save(event);
    }
}
