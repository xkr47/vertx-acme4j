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

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
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

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static io.vertx.core.http.ClientAuth.REQUEST;
import static io.vertx.core.http.HttpVersion.HTTP_1_1;
import static java.util.Arrays.asList;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.stream.Collectors.toList;

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
        new DynamicCertManager(vertx, dynamicCertOptions, "default").init();

        class State {
            PrivateKey key;
            Certificate[] chain;
            void keyBuffer(AsyncResult<Buffer> keyBuffer) {
                vertx.executeBlocking((Future<PrivateKey> fut) -> {
                    try {
                        fut.complete(PemLoader.loadPrivateKey(keyBuffer.result()));
                    } catch (Exception e) {
                        fut.fail(e);
                    }
                }, evt -> {
                    key = evt.result();
                    check();
                });
            }
            void certBuffer(AsyncResult<Buffer> certBuffer) {
                vertx.executeBlocking((Future<Certificate[]> fut) -> {
                    try {
                        fut.complete(PemLoader.loadCerts(certBuffer.result()));
                    } catch (Exception e) {
                        fut.fail(e);
                    }
                }, evt -> {
                    chain = evt.result();
                    check();
                });
            }
            void check() {
                if (key != null && chain != null) {
                    vertx.eventBus().publish("keystore.put", new DynamicCertManager.CertCombo("default", key, chain));
                }
            }
        }

        final State state = new State();
        vertx.fileSystem().readFile(tls.getString("serverKey"), state::keyBuffer);
        vertx.fileSystem().readFile(tls.getString("serverCert"), state::certBuffer);

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


    public static class DynamicCertManager {
        public static class CertCombo {
            String id; // for removing/updating later
            Certificate[] chain;
            PrivateKey key;

            public CertCombo(String id, PrivateKey key, Certificate[] chain) {
                this.id = id;
                this.key = key;
                this.chain = chain;
            }
        }

        private final Vertx vertx;
        private final DynamicCertOptions opts;
        private final String idOfDefaultAlias;
        private final Map<String, CertCombo> map = new HashMap<>();

        public DynamicCertManager(Vertx vertx, DynamicCertOptions opts, String idOfDefaultAlias) {
            this.vertx = vertx;
            this.opts = opts;
            this.idOfDefaultAlias = idOfDefaultAlias;
        }

        public void init() {
            vertx.eventBus().consumer("keystore.put", event -> {
                CertCombo cc = (CertCombo) event.body();
                CertCombo old = map.put(cc.id, cc);
                logger.info((old != null ? "Replacing" : "Installing") + " cert for " + cc.id);
                update();
            });

            vertx.eventBus().consumer("keystore.remove", event -> {
                String id = (String) event.body();
                CertCombo old = map.remove(id);
                logger.info((old != null ? "Removing cert" : "Nothing cert to remove") + " for " + id);
                update();
            });
        }

        void update() {
            try {
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, null);
                String defaultAlias = "dummy";
                for (CertCombo cc : map.values()) {
                    String defaultAliasCandidate = PemLoader.importKeyAndCertsToStore(keyStore, cc.key, cc.chain);
                    if (cc.id.equals(idOfDefaultAlias)) {
                        defaultAlias = defaultAliasCandidate;
                    }
                }
                logger.info("Reloading certificates: ", map.values().stream().map(cc -> cc.id).collect(toList()));
                opts.load(defaultAlias, keyStore, new char[0]);
            } catch (IOException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
