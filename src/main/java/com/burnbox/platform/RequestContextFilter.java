package com.burnbox.platform;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Filter that establishes the RequestContext and Java 25 Scoped Values for each request.
 * Sets X-Request-Id response header and binds MDC diagnostics.
 */
@Component("burnboxRequestContextFilter")
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestContextFilter extends OncePerRequestFilter {

    public static final String REQUEST_ID_HEADER = "X-Request-Id";
    public static final String MDC_REQUEST_ID = "request_id";
    public static final String MDC_USER_REF = "user_ref";

    private static final Pattern SAFE_REQUEST_ID = Pattern.compile("^[a-zA-Z0-9_-]{8,64}$");

    private final ObjectProvider<IpHasher> ipHasherProvider;

    public RequestContextFilter(ObjectProvider<IpHasher> ipHasherProvider) {
        this.ipHasherProvider = ipHasherProvider;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String requestId = resolveRequestId(request);
        response.setHeader(REQUEST_ID_HEADER, requestId);

        String ipHash = resolveIpHash(request);
        String actorUserId = resolveActor();

        RequestContext context = new RequestContext(requestId, actorUserId, ipHash);

        MDC.put(MDC_REQUEST_ID, requestId);
        if (actorUserId != null) {
            MDC.put(MDC_USER_REF, actorUserId);
        }

        try {
            RequestContext.runWith(context, () -> {
                try {
                    filterChain.doFilter(request, response);
                } catch (IOException | ServletException e) {
                    throw new FilterDispatchException(e);
                }
            });
        } catch (FilterDispatchException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException ioException) {
                throw ioException;
            } else if (cause instanceof ServletException servletException) {
                throw servletException;
            } else {
                throw new ServletException(cause);
            }
        } finally {
            MDC.remove(MDC_REQUEST_ID);
            MDC.remove(MDC_USER_REF);
        }
    }

    private String resolveRequestId(HttpServletRequest request) {
        String incomingId = request.getHeader(REQUEST_ID_HEADER);
        if (incomingId != null && SAFE_REQUEST_ID.matcher(incomingId.trim()).matches()) {
            return incomingId.trim();
        }
        return UUID.randomUUID().toString();
    }

    private String resolveIpHash(HttpServletRequest request) {
        IpHasher hasher = ipHasherProvider.getIfAvailable();
        String remoteAddr = request.getRemoteAddr();
        if (hasher != null) {
            return hasher.hashIp(remoteAddr);
        }
        return "0000000000000000000000000000000000000000000000000000000000000000";
    }

    private String resolveActor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            return auth.getName();
        }
        return null;
    }

    private static class FilterDispatchException extends RuntimeException {
        FilterDispatchException(Throwable cause) {
            super(cause);
        }
    }
}
