package com.burnbox.platform;

import java.util.Optional;
import java.util.concurrent.Callable;

/**
 * Request context propagated through Java 25 Scoped Values.
 * Holds request_id, actor and ip_hash without mutable ThreadLocal state.
 */
public record RequestContext(
        String requestId,
        String actorUserId,
        String ipHash
) {
    public static final ScopedValue<RequestContext> CURRENT = ScopedValue.newInstance();

    public static Optional<RequestContext> current() {
        return CURRENT.isBound() ? Optional.ofNullable(CURRENT.get()) : Optional.empty();
    }

    public static String currentRequestId() {
        return current().map(RequestContext::requestId).orElse("system");
    }

    public static Optional<String> currentActor() {
        return current().map(RequestContext::actorUserId);
    }

    public static Optional<String> currentIpHash() {
        return current().map(RequestContext::ipHash);
    }

    public static <T> T callWith(RequestContext context, Callable<T> callable) throws Exception {
        return ScopedValue.where(CURRENT, context).call(callable::call);
    }

    public static void runWith(RequestContext context, Runnable runnable) {
        ScopedValue.where(CURRENT, context).run(runnable);
    }
}
