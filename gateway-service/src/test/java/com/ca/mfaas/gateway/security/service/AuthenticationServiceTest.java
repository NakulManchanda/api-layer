/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */
package com.ca.mfaas.gateway.security.service;

import com.ca.apiml.security.common.config.AuthConfigurationProperties;
import com.ca.apiml.security.common.token.QueryResponse;
import com.ca.apiml.security.common.token.TokenAuthentication;
import com.ca.apiml.security.common.token.TokenExpireException;
import com.ca.apiml.security.common.token.TokenNotValidException;
import com.ca.mfaas.security.SecurityUtils;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.lang.time.DateUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.Cookie;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class AuthenticationServiceTest {

    private static final String USER = "Me";
    private static final String DOMAIN = "this.com";
    private static final String LTPA = "ltpaToken";
    private static final SignatureAlgorithm ALGORITHM = SignatureAlgorithm.RS256;

    private Key privateKey;
    private PublicKey publicKey;

    private AuthenticationService authService;
    private AuthConfigurationProperties authConfigurationProperties;

    @Mock
    private JwtSecurityInitializer jwtSecurityInitializer;

    @BeforeEach
    public void setUp() {
        KeyPair keyPair = SecurityUtils.generateKeyPair("RSA", 2048);
        if (keyPair != null) {
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        }
        Mockito.lenient().when(jwtSecurityInitializer.getSignatureAlgorithm()).thenReturn(ALGORITHM);
        Mockito.lenient().when(jwtSecurityInitializer.getJwtSecret()).thenReturn(privateKey);
        Mockito.lenient().when(jwtSecurityInitializer.getJwtPublicKey()).thenReturn(publicKey);

        authConfigurationProperties = new AuthConfigurationProperties();
        authService = new AuthenticationService(authConfigurationProperties, jwtSecurityInitializer);
    }

    @Test
    public void shouldCreateJwtToken() {
        String jwtToken = authService.createJwtToken(USER, DOMAIN, LTPA);

        assertFalse(jwtToken.isEmpty());
        assertEquals("java.lang.String", jwtToken.getClass().getName());
    }

    @Test()
    public void shouldThrowExceptionWithNullSecret() {
        when(jwtSecurityInitializer.getJwtSecret()).thenReturn(null);
        assertThrows(IllegalArgumentException.class, () -> {
            authService.createJwtToken(USER, DOMAIN, LTPA);
        });
    }

    @Test
    public void shouldValidateJwtToken() {
        String jwtToken = authService.createJwtToken(USER, DOMAIN, LTPA);

        TokenAuthentication token = new TokenAuthentication(jwtToken);
        TokenAuthentication jwtValidation = authService.validateJwtToken(token);

        assertEquals(USER, jwtValidation.getPrincipal());
        assertEquals(jwtValidation.getCredentials(), jwtToken);
        assertTrue(jwtValidation.isAuthenticated());
    }

    @Test
    public void shouldThrowExceptionWhenTokenIsInvalid() {
        String jwtToken = authService.createJwtToken(USER, DOMAIN, LTPA);
        String brokenToken = jwtToken + "not";
        TokenAuthentication token = new TokenAuthentication(brokenToken);
        assertThrows(TokenNotValidException.class, () -> {
            authService.validateJwtToken(token);
        });
    }

    @Test
    public void shouldThrowExceptionWhenTokenIsExpired() {
        TokenAuthentication token = new TokenAuthentication(createExpiredJwtToken(privateKey));
        assertThrows(TokenExpireException.class, () -> {
            authService.validateJwtToken(token);
        });
    }

    @Test
    public void shouldThrowExceptionWhenOccurUnexpectedException() {
        assertThrows(TokenNotValidException.class, () -> {
            authService.validateJwtToken(null);
        });
    }

    @Test
    public void shouldParseJwtTokenAsQueryResponse() {
        String jwtToken = authService.createJwtToken(USER, DOMAIN, LTPA);

        String dateNow = new Date().toString().substring(0, 16);
        QueryResponse parsedToken = authService.parseJwtToken(jwtToken);

        assertEquals("com.ca.apiml.security.common.token.QueryResponse", parsedToken.getClass().getTypeName());
        assertEquals(DOMAIN, parsedToken.getDomain());
        assertEquals(USER, parsedToken.getUserId());
        assertEquals(parsedToken.getCreation().toString().substring(0, 16), dateNow);
        Date toBeExpired = DateUtils.addDays(parsedToken.getCreation(), 1);
        assertEquals(parsedToken.getExpiration(), toBeExpired);
    }

    @Test
    public void shouldReadJwtTokenFromRequestCookie() {
        String jwtToken = authService.createJwtToken(USER, DOMAIN, LTPA);
        MockHttpServletRequest request = new MockHttpServletRequest();

        Optional<String> optionalToken = authService.getJwtTokenFromRequest(request);
        assertFalse(optionalToken.isPresent());

        request.setCookies(new Cookie("apimlAuthenticationToken", jwtToken));

        optionalToken = authService.getJwtTokenFromRequest(request);
        assertTrue(optionalToken.isPresent());
        assertEquals(optionalToken.get(), jwtToken);
    }

    @Test
    public void shouldExtractJwtFromRequestHeader() {
        String jwtToken = authService.createJwtToken(USER, DOMAIN, LTPA);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer ");
        Optional<String> optionalToken = authService.getJwtTokenFromRequest(request);
        assertFalse(optionalToken.isPresent());

        request = new MockHttpServletRequest();
        request.addHeader("Authorization", String.format("Bearer %s", jwtToken));
        optionalToken = authService.getJwtTokenFromRequest(request);
        assertTrue(optionalToken.isPresent());
        assertEquals(optionalToken.get(), jwtToken);
    }

    @Test
    public void shouldReadLtpaTokenFromJwtToken() {
        String jwtToken = authService.createJwtToken(USER, DOMAIN, LTPA);
        assertEquals(LTPA, authService.getLtpaTokenFromJwtToken(jwtToken));
    }

    @Test
    public void shouldThrowExceptionWhenTokenIsInvalidWhileExtractingLtpa() {
        String jwtToken = authService.createJwtToken(USER, DOMAIN, LTPA);
        String brokenToken = jwtToken + "not";
        assertThrows(TokenNotValidException.class, () -> {
            authService.getLtpaTokenFromJwtToken(brokenToken);
        });
    }

    @Test
    public void shouldThrowExceptionWhenTokenIsExpiredWhileExtractingLtpa() {
        assertThrows(TokenExpireException.class, () -> {
            authService.getLtpaTokenFromJwtToken(createExpiredJwtToken(privateKey));
        });
    }

    private String createExpiredJwtToken(Key secretKey) {
        long expiredTimeMillis = System.currentTimeMillis() - 1000;

        return Jwts.builder()
            .setExpiration(new Date(expiredTimeMillis))
            .setIssuer(authConfigurationProperties.getTokenProperties().getIssuer())
            .signWith(ALGORITHM, secretKey)
            .compact();
    }
}
