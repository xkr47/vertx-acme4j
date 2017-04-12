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

import io.vertx.core.buffer.Buffer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class PemLoader {
    // 99% copy-pasted code from vert.x KeyStoreHelper

    private static List<byte[]> loadPem(Buffer data, String delimiter) throws IOException {
        String pem = data.toString();
        String beginDelimiter = "-----BEGIN " + delimiter + "-----";
        String endDelimiter = "-----END " + delimiter + "-----";
        List<byte[]> pems = new ArrayList<>();
        int index = 0;
        while (true) {
            index = pem.indexOf(beginDelimiter, index);
            if (index == -1) {
                break;
            }
            index += beginDelimiter.length();
            int end = pem.indexOf(endDelimiter, index);
            if (end == -1) {
                throw new RuntimeException("Missing " + endDelimiter + " delimiter");
            }
            String content = pem.substring(index, end);
            content = content.replaceAll("\\s", "");
            if (content.length() == 0) {
                throw new RuntimeException("Empty pem file");
            }
            index = end + 1;
            pems.add(Base64.getDecoder().decode(content));
        }
        if (pems.isEmpty()) {
            throw new RuntimeException("Missing " + beginDelimiter + " delimiter");
        }
        return pems;
    }

    public static PrivateKey loadPrivateKey(Buffer keyValue) {
        if (keyValue == null) {
            throw new NullPointerException("Missing private key");
        }
        try {
            byte[] value = loadPem(keyValue, "PRIVATE KEY").get(0);
            KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
            return rsaKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(value));
        } catch (Exception e) {
            throw new RuntimeException("Problem loading private key", e);
        }
    }

    public static X509Certificate[] loadCerts(Buffer buffer) {
        if (buffer == null) {
            throw new NullPointerException("Missing X.509 certificate");
        }
        try {
            List<byte[]> pems = loadPem(buffer, "CERTIFICATE");
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certs = new ArrayList<>(pems.size());
            for (byte[] pem : pems) {
                for (Certificate cert : certFactory.generateCertificates(new ByteArrayInputStream(pem))) {
                    certs.add((X509Certificate) cert);
                }
            }
            return certs.toArray(new X509Certificate[certs.size()]);
        } catch (Exception e) {
            throw new RuntimeException("Problem loading certificate certWithChain", e);
        }
    }

}
