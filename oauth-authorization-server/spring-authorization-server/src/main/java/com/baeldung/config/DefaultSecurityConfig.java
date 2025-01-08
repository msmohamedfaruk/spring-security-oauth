package com.baeldung.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;

import com.baeldung.CustomCodeGrantAuthenticationConverter;
import com.baeldung.CustomCodeGrantAuthenticationProvider;
import com.baeldung.service.MyUserDetailsService;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class DefaultSecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(withDefaults())
                .tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint
                                .accessTokenRequestConverter(
                                        new CustomCodeGrantAuthenticationConverter())
                                .authenticationProvider(
                                        new CustomCodeGrantAuthenticationProvider(
                                                authorizationService, tokenGenerator)));

        return http.formLogin(withDefaults()).build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                        authorizeRequests -> authorizeRequests.anyRequest()
                                .authenticated())
                // uncomment, if we want to represent auth server as resource server
//                .oauth2ResourceServer(oauth -> oauth.jwt(withDefaults()))
                .formLogin(withDefaults());
        return http.build();
    }

    // commented since carrying the grant type extension via authorizationserver properties
//    @Bean
//    RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient messagingClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("messaging-client")
//                .clientSecret("{noop}secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(new AuthorizationGrantType(CUSTOM_GRANT_TYPE))
//                .scope("message.read")
//                .scope("message.write")
//                .build();
//
//        return new InMemoryRegisteredClientRepository(messagingClient);
//    }
//
    @Bean
    OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

//    @Bean
//    UserDetailsService users() {
//        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
//        UserDetails user = User.builder()
//                .username("admin")
//                .password("password")
//                .passwordEncoder(encoder::encode)
//                .roles("USER")
//                .build();
//        return new InMemoryUserDetailsManager(user);
//    }

    // added to rely on user details from JDBC

    @Bean
    UserDetailsService userDetailsService(){
        return (UserDetailsService) new MyUserDetailsService();
    }

    @Bean
    DaoAuthenticationProvider customDaoAuthenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        // defining passwordEncoder bean will prevent token api [CustomCodeGrantAuthenticationProvider]
        // authentication via noOpPasswordEncoder, hence declaring BCrypt only for DAOProvider
		daoAuthenticationProvider.setPasswordEncoder(new BCryptPasswordEncoder());
        return daoAuthenticationProvider;
    }

}