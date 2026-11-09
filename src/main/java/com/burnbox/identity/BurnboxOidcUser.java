package com.burnbox.identity;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.*;

public class BurnboxOidcUser implements OidcUser {

    private final OidcUser delegate;
    private final AppUser appUser;
    private final Set<GrantedAuthority> authorities;

    public BurnboxOidcUser(OidcUser delegate, AppUser appUser) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.appUser = Objects.requireNonNull(appUser, "appUser must not be null");

        Set<GrantedAuthority> auths = new HashSet<>(delegate.getAuthorities());
        auths.add(new SimpleGrantedAuthority("ROLE_USER"));
        this.authorities = Collections.unmodifiableSet(auths);
    }

    public AppUser getAppUser() {
        return appUser;
    }

    public UUID getUserId() {
        return appUser.id();
    }

    @Override
    public Map<String, Object> getClaims() {
        return delegate.getClaims();
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return delegate.getUserInfo();
    }

    @Override
    public OidcIdToken getIdToken() {
        return delegate.getIdToken();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return delegate.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getName() {
        return appUser.displayName() != null ? appUser.displayName() : delegate.getName();
    }
}
