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
package space.xkr47.vertx.acme4j.util;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;

public class KeyStoreUtil {
    /**
     * @return primary (subject) name of the certificate
     */
    public static String importKeyAndCertsToStore(KeyStore keyStore, PrivateKey key, Certificate[] certWithChain) throws Exception {
        KeyStore.PrivateKeyEntry pke = new KeyStore.PrivateKeyEntry(key, certWithChain);
        KeyStore.PasswordProtection pass = new KeyStore.PasswordProtection(new char[0]);
        List<String> certSubjectCn = getCertSubjectCn(certWithChain[0]);
        for (String alias : certSubjectCn) {
            keyStore.setEntry(alias, pke, pass);
        }
        for (String alias : getCertSan(certWithChain[0])) {
            keyStore.setEntry(alias, pke, pass);
        }
        return certSubjectCn.get(0);
    }

    private static List<String> getCertSubjectCn(Certificate cert) throws InvalidNameException {
        return new LdapName(((X509Certificate)cert).getSubjectDN().getName())
                .getRdns()
                .stream()
                .filter(rdn -> rdn.getType().equalsIgnoreCase("CN"))
                .map(rdn -> (String)rdn.getValue())
                .collect(toList());
    }

    private static List<String> getCertSan(Certificate cert) throws CertificateParsingException {
        Collection<List<?>> san = ((X509Certificate) cert).getSubjectAlternativeNames();
        if (san == null) return emptyList();
        return san.stream()
                .filter(list->list.get(0) == (Integer)2)
                .map(list -> (String)list.get(1))
                .collect(toList());
    }
}
