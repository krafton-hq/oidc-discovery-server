/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.krafton.sbx.plugins.pulsar.broker.authentication.oidc;

import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataCommand;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.Properties;
import java.util.Set;

// TODO: populate issuer, jwt field
public class AuthenticationProviderOpenIDIntegrationTest {

    AuthenticationProviderOpenID provider;
    String issuer;

    @BeforeClass
    void beforeClass() throws IOException {
        issuer = "<issuer here>";

        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setAuthenticationEnabled(true);
        conf.setAuthenticationProviders(Set.of(AuthenticationProviderOpenID.class.getName()));
        Properties props = conf.getProperties();
        props.setProperty(AuthenticationProviderOpenID.DISCOVERY_ISSUER, issuer);
        props.setProperty(AuthenticationProviderOpenID.FALLBACK_DISCOVERY_MODE, FallbackDiscoveryMode.HTTP_DISCOVER_TRUSTED_ISSUER.name());
        props.setProperty(AuthenticationProviderOpenID.ALLOWED_AUDIENCES, "https://kubernetes.default.svc");

        provider = new AuthenticationProviderOpenID();
        provider.initialize(conf);
    }

    @Test
    public void testHTTPDiscoveryIssuerFlowWithServiceAccountToken() throws Exception {
        var jwt = "<jwt here>";

        provider.authenticateAsync(new AuthenticationDataCommand(jwt)).get();
    }
}
