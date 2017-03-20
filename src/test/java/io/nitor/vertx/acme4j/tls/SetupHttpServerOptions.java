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
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.JdkSSLEngineOptions;
import io.vertx.core.net.OpenSSLEngineOptions;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.vertx.core.http.HttpVersion.HTTP_1_1;
import static java.util.Arrays.asList;
import static java.util.stream.Collectors.toList;

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

    public static HttpServerOptions createHttpServerOptions(Vertx vertx) {
        HttpServerOptions httpOptions = new HttpServerOptions()
                // basic TCP/HTTP options
                .setReuseAddress(true)
                .setCompressionSupported(false) // otherwise it automatically compresses based on response headers even if pre-compressed with e.g. proxy
                .setUsePooledBuffers(true);

        DynamicCertOptions dynamicCertOptions = new DynamicCertOptions();
        httpOptions
                .setSsl(true)
                .setKeyCertOptions(dynamicCertOptions)
                // TLS tuning
                .addEnabledSecureTransportProtocol("TLSv1.2")
                .addEnabledSecureTransportProtocol("TLSv1.3");

        // server side certificates
        DynamicCertManager.init(vertx, dynamicCertOptions, "default");

        vertx.executeBlocking(future -> {
            future.complete(new AcmeManager());
        }, false, ar -> {
            logger.info("AcmeManager completed", ar.cause());
        });

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

    public static class DynamicCertManager {
        static final Logger logger = LogManager.getLogger(DynamicCertManager.class);

        public static class CertCombo {
            String id; // for removing/updating later
            Certificate[] certWithChain;
            PrivateKey key;

            public CertCombo(String id, PrivateKey key, Certificate[] certWithChain) {
                this.id = id;
                this.key = key;
                this.certWithChain = certWithChain;
            }
        }

        private static Vertx vertx;
        private static DynamicCertOptions opts;
        private static String idOfDefaultAlias;
        private static Map<String, CertCombo> map = new HashMap<>();

        public static void init(Vertx vertx, DynamicCertOptions opts, String idOfDefaultAlias) {
            DynamicCertManager.vertx = vertx;
            DynamicCertManager.opts = opts;
            DynamicCertManager.idOfDefaultAlias = idOfDefaultAlias;
        }

        public static void put(String id, PrivateKey key, Certificate cert, Certificate... chain) {
            put(id, key, merge(cert, chain));
        }

        public static Certificate[] merge(Certificate cert, Certificate[] chain) {
            Certificate[] result = new Certificate[chain.length + 1];
            result[0] = cert;
            System.arraycopy(chain, 0, result, 1, chain.length);
            return result;
        }

        public static void put(String id, PrivateKey key, Certificate[] certWithChain) {
            put(new CertCombo(id, key, certWithChain));
        }

        public static synchronized void put(CertCombo cc) {
            CertCombo old = map.put(cc.id, cc);
            logger.info((old != null ? "Replacing" : "Installing") + " cert for " + cc.id);
            update();
        }

        public static synchronized void remove(String id) {
            CertCombo old = map.remove(id);
            logger.info((old != null ? "Removing cert" : "Nothing cert to remove") + " for " + id);
            update();
        }

        private static void update() {
            try {
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, null);
                String defaultAlias = "dummy";
                for (CertCombo cc : map.values()) {
                    String defaultAliasCandidate = PemLoader.importKeyAndCertsToStore(keyStore, cc.key, cc.certWithChain);
                    if (cc.id.equals(idOfDefaultAlias)) {
                        defaultAlias = defaultAliasCandidate;
                    }
                }
                logger.info("Reloading certificates: {}", map.values().stream().map(cc -> cc.id).collect(toList()));
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
