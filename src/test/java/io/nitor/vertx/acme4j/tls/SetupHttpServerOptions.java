/*
 * Copyright 2016-2017 Nitor Creations Oy, Jonas Berlin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.nitor.vertx.acme4j.tls;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.JdkSSLEngineOptions;
import io.vertx.core.net.OpenSSLEngineOptions;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;

import static java.util.Arrays.asList;

public class SetupHttpServerOptions {
    // syntax is in JVM SSL format
    private static final List<String> cipherSuites = asList(
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    );
    private static final boolean USE_OPENSSL = false;

    static final Logger logger = LogManager.getLogger(SetupHttpServerOptions.class);

    public static HttpServerOptions createHttpServerOptions(Vertx vertx, DynamicCertOptions dynamicCertOptions) {
        HttpServerOptions httpOptions = new HttpServerOptions()
                // basic TCP/HTTP options
                .setReuseAddress(true)
                .setCompressionSupported(false) // otherwise it automatically compresses based on response headers even if pre-compressed with e.g. proxy
                .setUsePooledBuffers(true)
                .setSsl(true)
                .setKeyCertOptions(dynamicCertOptions)
                // TLS tuning
                .addEnabledSecureTransportProtocol("TLSv1.2")
                .addEnabledSecureTransportProtocol("TLSv1.3");

        if (USE_OPENSSL) {
            // TODO this has not really been tested with SNI yet
            httpOptions
                    .setUseAlpn(true)
                    .setSslEngineOptions(new OpenSSLEngineOptions());
            cipherSuites.stream().map(SetupHttpServerOptions::javaCipherNameToOpenSSLName)
                    .forEach(httpOptions::addEnabledCipherSuite);
        } else {
            httpOptions
                    .setUseAlpn(DynamicAgent.enableJettyAlpn())
                    .setJdkSslEngineOptions(new JdkSSLEngineOptions());
            cipherSuites.forEach(httpOptions::addEnabledCipherSuite);
        }

        return httpOptions;
    }

    static String javaCipherNameToOpenSSLName(String name) {
        return name.replace("TLS_", "")
                .replace("WITH_AES_", "AES")
                .replace('_', '-');
    }

}
