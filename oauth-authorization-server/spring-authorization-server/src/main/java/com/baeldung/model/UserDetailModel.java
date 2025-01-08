package com.baeldung.model;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.baeldung.entity.Authorities;
import com.baeldung.entity.UserInfo;

public class UserDetailModel implements UserDetails {

    private String username;
    private String password;
    private List<GrantedAuthority> authorities;

    public UserDetailModel(UserInfo user){
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.authorities = user.getRoles().stream()
                .map(this::CustomGrantAuthority).collect(Collectors.toList());
    }

    SimpleGrantedAuthority CustomGrantAuthority(Authorities authorities){
        return new SimpleGrantedAuthority(authorities.getAuthority());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { return this.authorities; }

    @Override
    public String getPassword() { return this.password; }

    @Override
    public String getUsername() { return this.username; }

	// override the default value to true
    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }

}