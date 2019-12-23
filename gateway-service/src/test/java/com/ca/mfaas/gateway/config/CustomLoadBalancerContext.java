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

import com.netflix.client.config.IClientConfig;
import com.netflix.loadbalancer.ILoadBalancer;
import com.netflix.loadbalancer.LoadBalancerContext;

public class CustomLoadBalancerContext extends LoadBalancerContext {
    public CustomLoadBalancerContext(ILoadBalancer lb, IClientConfig clientConfig) {
        super(lb, clientConfig);
    }

    public CustomLoadBalancerContext(ILoadBalancer lb) {
        super(lb);
    }
}
