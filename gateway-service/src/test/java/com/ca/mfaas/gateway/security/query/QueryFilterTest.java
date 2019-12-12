/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */
package com.ca.mfaas.gateway.security.query;

import com.ca.apiml.security.common.error.AuthMethodNotSupportedException;
import com.ca.apiml.security.common.token.TokenNotProvidedException;
import com.ca.mfaas.gateway.security.service.AuthenticationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.ws.rs.HttpMethod;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class QueryFilterTest {
    private MockHttpServletRequest httpServletRequest;
    private MockHttpServletResponse httpServletResponse;
    private QueryFilter queryFilter;

    private final String VALID_TOKEN = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJNZSIsImRvbSI6InRoaXMuY29tIiwibHRwYSI6Imx0cGFUb2tlbiIsImlhdCI6MTU1NDg4MzMzNCwiZXhwIjoxNTU0OTY5NzM0LCJpc3MiOiJBUElNTCIsImp0aSI6IjNkMzU3M2VhLWMxMzktNGE5Yy1iZDU5LWVjYmIyMmM0ZDcxZCJ9.bLe_d3b3bZC-K5K49fj1aHL_xDWMPsAgwKkrfewOrHhrxVL6lSphpGx52b8YvjaMUkFpVO12jCEDoYC1JLaQhQ";

    @Mock
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    @Mock
    private AuthenticationFailureHandler authenticationFailureHandler;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private AuthenticationService authenticationService;

    @BeforeEach
    public void setup() {
        queryFilter = new QueryFilter("TEST_ENDPOINT",
            authenticationSuccessHandler,
            authenticationFailureHandler,
            authenticationService,
            authenticationManager);
    }

    @Test
    public void shouldCallAuthenticationManagerAuthenticate() {
        httpServletRequest = new MockHttpServletRequest();
        httpServletRequest.setMethod(HttpMethod.GET);
        httpServletResponse = new MockHttpServletResponse();
        queryFilter.setAuthenticationManager(authenticationManager);
        when(authenticationService.getJwtTokenFromRequest(any())).thenReturn(
            Optional.of(VALID_TOKEN)
        );

        queryFilter.attemptAuthentication(httpServletRequest, httpServletResponse);

        verify(authenticationManager).authenticate(any());
    }

    @Test
    public void shouldRejectHttpMethods() {
        httpServletRequest = new MockHttpServletRequest();
        httpServletRequest.setMethod(HttpMethod.POST);
        httpServletResponse = new MockHttpServletResponse();
        assertThrows(AuthMethodNotSupportedException.class, () -> {
            queryFilter.attemptAuthentication(httpServletRequest, httpServletResponse);
        });
    }

    @Test
    public void shouldRejectIfTokenIsNotPresent() {
        httpServletRequest = new MockHttpServletRequest();
        httpServletRequest.setMethod(HttpMethod.GET);
        httpServletResponse = new MockHttpServletResponse();
        assertThrows(TokenNotProvidedException.class, () -> {
                queryFilter.attemptAuthentication(httpServletRequest, httpServletResponse);
            });

        Mockito.lenient().when(authenticationService.getJwtTokenFromRequest(any())).thenReturn(
            Optional.empty()
        );

    }
}
