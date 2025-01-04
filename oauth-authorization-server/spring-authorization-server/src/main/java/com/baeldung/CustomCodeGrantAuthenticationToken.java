package com.baeldung;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class CustomCodeGrantAuthenticationToken extends UsernamePasswordAuthenticationToken {

    public static final String CUSTOM_GRANT_TYPE="urn:ietf:params:oauth:grant-type:custom_code";

    public static final Set<String> AUTHORIZED_SCOPES = new HashSet<>();

    static {
        AUTHORIZED_SCOPES.add("articles.read");
    }

    private AuthorizationGrantType grantType;

    public CustomCodeGrantAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
        this.grantType = new AuthorizationGrantType(CUSTOM_GRANT_TYPE);
    }

    public AuthorizationGrantType getGrantType() {
        return grantType;
    }
}
