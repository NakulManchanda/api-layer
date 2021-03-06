/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */
package com.ca.mfaas.gateway.config;

import com.ca.mfaas.product.gateway.GatewayConfigProperties;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class GatewayConfigTest {

    private static final String HOST = "hostA";
    private static final String PORT = "8888";
    private static final String SCHEME = "https";

    @Test
    public void shouldReturnGatewayProperties() {
        GatewayConfigProperties gatewayConfigProperties = new GatewayConfig().getGatewayConfigProperties(HOST, PORT, SCHEME);
        assertEquals(HOST + ":" + PORT, gatewayConfigProperties.getHostname());
        assertEquals(SCHEME, gatewayConfigProperties.getScheme());
    }
}
