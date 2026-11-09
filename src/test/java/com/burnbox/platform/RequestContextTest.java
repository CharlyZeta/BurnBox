package com.burnbox.platform;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class RequestContextTest {

    private final IpHasher mockIpHasher = ip -> "hash_of_" + ip;
    private final RequestContextFilter filter = new RequestContextFilter(
            new org.springframework.beans.factory.support.StaticListableBeanFactory() {
                @Override
                @SuppressWarnings("unchecked")
                public <T> org.springframework.beans.factory.ObjectProvider<T> getBeanProvider(Class<T> requiredType) {
                    return new org.springframework.beans.factory.ObjectProvider<>() {
                        @Override
                        public T getObject(Object... args) {
                            return (T) mockIpHasher;
                        }

                        @Override
                        public T getIfAvailable() {
                            return (T) mockIpHasher;
                        }

                        @Override
                        public T getIfUnique() {
                            return (T) mockIpHasher;
                        }

                        @Override
                        public T getObject() {
                            return (T) mockIpHasher;
                        }
                    };
                }
            }.getBeanProvider(IpHasher.class)
    );

    @Test
    @DisplayName("AC-001 / BR-002: RequestContextFilter propaga request_id mediante Scoped Value y cabecera HTTP")
    void requestIdPropagatedViaScopedValueAndHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        AtomicReference<String> capturedRequestId = new AtomicReference<>();

        filter.doFilter(request, response, (req, res) -> {
            capturedRequestId.set(RequestContext.currentRequestId());
        });

        String responseHeader = response.getHeader(RequestContextFilter.REQUEST_ID_HEADER);
        assertThat(responseHeader).isNotNull().isNotBlank();
        assertThat(capturedRequestId.get()).isEqualTo(responseHeader);
        assertThat(RequestContext.current()).isEmpty(); // Limpio fuera del request
    }

    @Test
    @DisplayName("AC-001: RequestContextFilter preserva X-Request-Id seguro entrante")
    void existingSafeRequestIdPreserved() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(RequestContextFilter.REQUEST_ID_HEADER, "custom-trace-uuid-1234");
        MockHttpServletResponse response = new MockHttpServletResponse();

        AtomicReference<String> capturedRequestId = new AtomicReference<>();

        filter.doFilter(request, response, (req, res) -> {
            capturedRequestId.set(RequestContext.currentRequestId());
        });

        assertThat(capturedRequestId.get()).isEqualTo("custom-trace-uuid-1234");
        assertThat(response.getHeader(RequestContextFilter.REQUEST_ID_HEADER)).isEqualTo("custom-trace-uuid-1234");
    }

    @Test
    @DisplayName("AC-002 / AF-01: Request anónimo asigna actor vacío y calcula ip_hash")
    void anonymousRequestHasNoActorAndCalculatesIpHash() throws Exception {
        SecurityContextHolder.clearContext();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.100");
        MockHttpServletResponse response = new MockHttpServletResponse();

        AtomicReference<String> capturedActor = new AtomicReference<>();
        AtomicReference<String> capturedIpHash = new AtomicReference<>();

        filter.doFilter(request, response, (req, res) -> {
            capturedActor.set(RequestContext.currentActor().orElse(null));
            capturedIpHash.set(RequestContext.currentIpHash().orElse(null));
        });

        assertThat(capturedActor.get()).isNull();
        assertThat(capturedIpHash.get()).isEqualTo("hash_of_192.168.1.100");
    }

    @Test
    @DisplayName("AC-002: Request autenticado propaga identificador de usuario")
    void authenticatedRequestPropagatesActor() throws Exception {
        var auth = new UsernamePasswordAuthenticationToken(
                "user-uuid-9999",
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);
        try {
            MockHttpServletRequest request = new MockHttpServletRequest();
            MockHttpServletResponse response = new MockHttpServletResponse();

            AtomicReference<String> capturedActor = new AtomicReference<>();

            filter.doFilter(request, response, (req, res) -> {
                capturedActor.set(RequestContext.currentActor().orElse(null));
            });

            assertThat(capturedActor.get()).isEqualTo("user-uuid-9999");
        } finally {
            SecurityContextHolder.clearContext();
        }
    }
}
