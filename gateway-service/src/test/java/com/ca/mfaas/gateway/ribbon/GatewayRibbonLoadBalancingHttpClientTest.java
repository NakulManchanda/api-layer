/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */

package com.ca.mfaas.gateway.ribbon;

import com.ca.mfaas.gateway.config.CustomLoadBalancerContext;
import com.netflix.client.ClientException;
import com.netflix.client.config.DefaultClientConfigImpl;
import com.netflix.client.config.IClientConfig;
import com.netflix.loadbalancer.*;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.cloud.netflix.ribbon.DefaultServerIntrospector;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(SpringExtension.class)
@TestPropertySource(locations = "/application.yml")
@ContextConfiguration(initializers = ConfigFileApplicationContextInitializer.class)
@Import(GatewayRibbonLoadBalancingHttpClientTest.TestConfiguration.class)
class GatewayRibbonLoadBalancingHttpClientTest {

    private GatewayRibbonLoadBalancingHttpClient gatewayRibbonLoadBalancingHttpClient;
    private CloseableHttpClient closeableHttpClient;
    private IClientConfig iClientConfig;
    final static Object httpKey = "http";
    final static Object httpsKey = "https";
    private CustomLoadBalancerContext context;
    @Autowired
    private DefaultServerIntrospector defaultServerIntrospector;

    static BaseLoadBalancer mixedSchemeLb = new BaseLoadBalancer() {

        @Override
        public Server chooseServer(Object key) {
            if (key == httpKey) {
                return new Server("http://localhost:10014");
            } else if (key == httpsKey) {
                return new Server("https://localhost:10014");
            }

            return new Server("https://localhost:10014");
        }
    };
    static BaseLoadBalancer lb = new BaseLoadBalancer() {

        @Override
        public Server chooseServer(Object key) {
            return new Server("https://localhost:10014");
        }
    };


    public GatewayRibbonLoadBalancingHttpClientTest() {
        context = new CustomLoadBalancerContext(lb);
    }


    @BeforeEach
    public void setup() {
        closeableHttpClient = mock(CloseableHttpClient.class);
        iClientConfig = IClientConfig.Builder.newBuilder(DefaultClientConfigImpl.class, "apicatalog").withSecure(false).withFollowRedirects(false).withDeploymentContextBasedVipAddresses("apicatalog").withLoadBalancerEnabled(false).build();
        gatewayRibbonLoadBalancingHttpClient = new GatewayRibbonLoadBalancingHttpClient(closeableHttpClient, iClientConfig, defaultServerIntrospector);
    }

    @Test
    public void should() throws ClientException, URISyntaxException {
        HttpGet httpGet = mock(HttpGet.class);
        CloseableHttpResponse closeableHttpResponse = mock(CloseableHttpResponse.class);
        try {
            when(closeableHttpClient.execute(httpGet)).thenReturn(closeableHttpResponse);
        } catch (IOException e) {
            e.printStackTrace();
        }
        URI request = new URI("/apicatalog/");

        context = new CustomLoadBalancerContext(mixedSchemeLb, iClientConfig);
        Server server = context.getServerFromLoadBalancer(request, httpsKey);
        server.setZone("defaultZone");
        server.setAlive(true);
        server.setReadyToServe(true);
        gatewayRibbonLoadBalancingHttpClient.reconstructURIWithServer(server, request);
    }
    @Configuration
    protected static class TestConfiguration {

        @Bean
        public DefaultServerIntrospector defaultServerIntrospector() {
            return new DefaultServerIntrospector();
        }

    }

}
