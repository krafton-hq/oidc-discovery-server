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

import com.auth0.jwt.JWT;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultJwtBuilder;
import io.jsonwebtoken.security.Keys;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataCommand;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.testng.asserts.Assertion;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.Properties;
import java.util.Set;

// TODO: populate issuer, jwt field
public class AuthenticationProviderOpenIDIntegrationTest {
    PrivateKey privateKey;
    PublicKey publicKey;
    AuthenticationProviderOpenID provider;
    String issuer;

    @BeforeClass
    void beforeClass() throws IOException {
        issuer = "<issuer here>";

        var keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setAuthenticationEnabled(true);
        conf.setAuthenticationProviders(Set.of(AuthenticationProviderOpenID.class.getName()));
        Properties props = conf.getProperties();
        props.setProperty(AuthenticationProviderOpenID.DISCOVERY_ISSUER, issuer);
        props.setProperty(AuthenticationProviderOpenID.FALLBACK_DISCOVERY_MODE, FallbackDiscoveryMode.HTTP_DISCOVER_TRUSTED_ISSUER.name());
        props.setProperty(AuthenticationProviderOpenID.ALLOWED_AUDIENCES, "https://kubernetes.default.svc");
        props.setProperty(AuthenticationProviderOpenID.ALLOWED_EMPTY_AUD_ISSUERS, "kubernetes/serviceaccount");

        provider = new AuthenticationProviderOpenID();
        provider.initialize(conf);
    }

    @Test
    public void testHTTPDiscoveryIssuerFlowWithServiceAccountToken() throws Exception {
        var jwt = "<jwt here>";

        provider.authenticateAsync(new AuthenticationDataCommand(jwt)).get();
    }

    @Test
    public void testNullAudClaimForAllowedIssuer() throws Exception {
        var jwt = this.generateToken("kubernetes/serviceaccount");

        var decodedJwt = JWT.decode(jwt);
        provider.verifyJWT(this.publicKey, "RS256", decodedJwt);

        var jwt2 = this.generateToken("unknown-issuer");
        var decodedJwt2 = JWT.decode(jwt2);
        Assert.assertThrows(() -> provider.verifyJWT(this.publicKey, "RS256", decodedJwt2));
    }

    private String generateToken(String issuer) {
        var now = System.currentTimeMillis();

        var builder = new DefaultJwtBuilder();

        builder.signWith(this.privateKey);
        builder.setIssuer(issuer);
        builder.setIssuedAt(new Date());
        builder.setExpiration(new Date(now + 99999999));
        builder.setNotBefore(new Date());
        builder.setSubject("system:serviceaccount:default:default");

        return builder.compact();
    }
}
