/**
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
package io.nitor.api.backend.tls;

import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.JdkSSLEngineOptions;
import io.vertx.core.net.OpenSSLEngineOptions;
import io.vertx.core.net.PemTrustOptions;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.shredzone.acme4j.util.CertificateUtils;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import static io.vertx.core.http.ClientAuth.REQUEST;
import static io.vertx.core.http.HttpVersion.HTTP_1_1;
import static java.util.Arrays.asList;
import static java.util.concurrent.TimeUnit.MINUTES;

public class SetupHttpServerOptions {
    // syntax is in JVM SSL format
    private static final List<String> cipherSuites = asList(
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    );

    static final Logger logger = LogManager.getLogger(SetupHttpServerOptions.class);

    public static HttpServerOptions createHttpServerOptions(Vertx vertx, JsonObject config) {
        JsonObject tls = config.getJsonObject("tls");
        DynamicCertOptions dynamicCertOptions = new DynamicCertOptions();
        HttpServerOptions httpOptions = new HttpServerOptions()
                // basic TCP/HTTP options
                .setReuseAddress(true)
                .setCompressionSupported(false) // otherwise it automatically compresses based on response headers even if pre-compressed with e.g. proxy
                .setUsePooledBuffers(true)
                // TODO: upcoming in vertx 3.4+ .setCompressionLevel(2)
                .setIdleTimeout(config.getInteger("idleTimeout", (int) MINUTES.toSeconds(10)))
                .setSsl(true)
                .setKeyCertOptions(dynamicCertOptions)
                // TLS tuning
                .addEnabledSecureTransportProtocol("TLSv1.2")
                .addEnabledSecureTransportProtocol("TLSv1.3");

        // server side certificates
        class State {
            Buffer keyBuffer, certBuffer;
            void check() {
                if (keyBuffer != null && certBuffer != null) {
                    try {
                        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                        keyStore.load(null, null);
                        String defaultAlias = PemLoader.importKeyAndCertsToStore(keyStore, PemLoader.loadPrivateKey(keyBuffer), PemLoader.loadCerts(certBuffer));

                        KeyPair sniKeyPair = KeyPairUtils.createKeyPair(2048);
                        X509Certificate cert = CertificateUtils.createTlsSni02Certificate(sniKeyPair, "lol1", "lol2");
                        PemLoader.importKeyAndCertsToStore(keyStore, sniKeyPair.getPrivate(), new Certificate[] { cert });

                        dynamicCertOptions.load(defaultAlias, keyStore, new char[0]);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }
        final State state = new State();
        vertx.fileSystem().readFile(tls.getString("serverKey"), keyBuffer -> { state.keyBuffer = keyBuffer.result(); state.check(); });
        vertx.fileSystem().readFile(tls.getString("serverCert"), certBuffer -> { state.certBuffer = certBuffer.result(); state.check(); });

        if (!config.getBoolean("http2", true)) {
            httpOptions.setAlpnVersions(asList(HTTP_1_1));
        }
        JsonObject clientAuth = config.getJsonObject("clientAuth");
        if (clientAuth != null && clientAuth.getString("clientChain") != null) {
            // client side certificate
                httpOptions.setClientAuth(REQUEST)
                    .setTrustOptions(new PemTrustOptions()
                            .addCertPath(clientAuth.getString("clientChain"))
                    );
        }
        if (config.getBoolean("useNativeOpenSsl")) {
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
