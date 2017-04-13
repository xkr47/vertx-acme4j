/*
 * Copyright 2017 Jonas Berlin
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
package io.nitor.vertx.acme4j.util;

import io.vertx.core.Vertx;
import io.vertx.core.logging.Logger;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import static io.vertx.core.logging.LoggerFactory.getLogger;
import static java.util.stream.Collectors.toList;

public class DynamicCertManager {
    static final Logger logger = getLogger(DynamicCertManager.class);

    public static class CertCombo {
        public final String id; // for removing/updating later
        public final Certificate[] certWithChain;
        public final PrivateKey key;

        public CertCombo(String id, PrivateKey key, Certificate[] certWithChain) {
            this.id = id;
            this.key = key;
            this.certWithChain = certWithChain;
        }
    }

    private final Vertx vertx;
    private final DynamicCertOptions opts;
    private final Map<String, CertCombo> map = new HashMap<>();
    private String idOfDefaultAlias;

    public DynamicCertManager(Vertx vertx, DynamicCertOptions opts) {
        this.vertx = vertx;
        this.opts = opts;
    }

    public void put(String id, boolean defaultCert, PrivateKey key, Certificate cert, Certificate... chain) {
        put(id, defaultCert, key, merge(cert, chain));
    }

    public static Certificate[] merge(Certificate cert, Certificate[] chain) {
        Certificate[] result = new Certificate[chain.length + 1];
        result[0] = cert;
        System.arraycopy(chain, 0, result, 1, chain.length);
        return result;
    }

    public void put(String id, boolean defaultCert, PrivateKey key, Certificate[] certWithChain) {
        put(new CertCombo(id, key, certWithChain), defaultCert);
    }

    public synchronized CertCombo get(String certificateId) {
        return map.get(certificateId);
    }

    /**
     * @param idOfDefaultAlias null (or non-matching id) gives no default cert
     */
    public synchronized void setIdOfDefaultAlias(String idOfDefaultAlias) {
        logger.info("Setting default cert to " + idOfDefaultAlias);
        if (this.idOfDefaultAlias != idOfDefaultAlias) {
            this.idOfDefaultAlias = idOfDefaultAlias;
            update();
        }
    }

    public synchronized String getIdOfDefaultAlias() {
        return idOfDefaultAlias;
    }

    public synchronized void put(CertCombo cc, boolean defaultCert) {
        CertCombo old = map.put(cc.id, cc);
        logger.info((old != null ? "Replacing" : "Installing") + " cert for " + cc.id);
        if (defaultCert) {
            logger.info("Setting default cert to " + cc.id);
            this.idOfDefaultAlias = cc.id;
        }
        update();
    }

    public synchronized void remove(String id) {
        CertCombo old = map.remove(id);
        logger.info((old != null ? "Removing cert" : "Nothing cert to remove") + " for " + id);
        update();
    }

    private void update() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            String defaultAlias = null;
            for (CertCombo cc : map.values()) {
                String defaultAliasCandidate = KeyStoreUtil.importKeyAndCertsToStore(keyStore, cc.key, cc.certWithChain);
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
