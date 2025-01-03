package com.baeldung;

import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class CustomCodeGrantAuthenticationToken extends UsernamePasswordAuthenticationToken {

    public static final String CUSTOM_GRANT_TYPE="urn:ietf:params:oauth:grant-type:custom_code";

    private AuthorizationGrantType grantType;

    public CustomCodeGrantAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
        this.grantType = new AuthorizationGrantType(CUSTOM_GRANT_TYPE);
    }

    public AuthorizationGrantType getGrantType() {
        return grantType;
    }
}
