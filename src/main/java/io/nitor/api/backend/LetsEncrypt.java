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
package io.nitor.api.backend;

import io.nitor.api.backend.tls.SetupHttpServerOptions.DynamicCertManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.TlsSni01Challenge;
import org.shredzone.acme4j.challenge.TlsSni02Challenge;
import org.shredzone.acme4j.exception.AcmeConflictException;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.exception.AcmeUnauthorizedException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.CertificateUtils;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.function.Supplier;

public class LetsEncrypt {

    static final String DOMAIN_KEY_PAIR_FILE = "letsencrypt-keypair.pem";
    static final String DOMAIN_ACCOUNT_LOCATION_FILE = "letsencrypt-accountLocation.txt";
    static final String CONTACT_EMAIL = null;
    static final String[] DOMAIN_NAMES = { "a139189489518.example.org" };
    static final String ORGANIZATION = "The Example Organization";

    static final String ACME_SERVER_URI = "acme://letsencrypt.org/staging";

    static final String AGREEMENT_URI = "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf";

    private static Logger logger = LogManager.getLogger(LetsEncrypt.class);

    public LetsEncrypt() {
        try {
            KeyPair accountKeyPair = getOrCreateAccountKeyPair();
            Session session = new Session(new URI(ACME_SERVER_URI), accountKeyPair);
            logger.info("Session set up");
            Registration registration = getOrCreateRegistration(session);
            logger.info("Domains to authorize: {}", DOMAIN_NAMES);
            for (String domainName : DOMAIN_NAMES) {
                logger.info("Authorizing domain {}", domainName);
                Authorization auth;
                try {
                    auth = registration.authorizeDomain(domainName);
                } catch (AcmeUnauthorizedException e) {
                    if (registration.getAgreement().equals(AGREEMENT_URI)) {
                        logger.info("Agreeing to " + AGREEMENT_URI);
                        registration.modify().setAgreement(new URI(AGREEMENT_URI)).commit();
                        auth = registration.authorizeDomain(domainName);
                    } else {
                        throw new RuntimeException("You need to agree to the Subscriber Agreement at: " + registration.getAgreement(), e);
                    }
                }
                logger.info("Domain {} authorized", domainName);
                logger.info("Challenge combinations supported: " + auth.getCombinations());
                Collection<Challenge> combination = auth.findCombination(SUPPORTED_CHALLENGES);
                logger.info("Challenges to complete: " + combination);
                for (Challenge challenge : combination) {
                    executeChallenge(domainName, challenge);
                }
                logger.info("Domain {} successfully associated with account", domainName);
            }
            logger.info("All domains successfully associated with account");
            createCertificate(registration, DOMAIN_NAMES, ORGANIZATION);
            logger.info("Certificate successfully activated. All done.");
        } catch (Exception e) {
            throw new RuntimeException("LetsEncrypt error", e);
        }
    }

    private void createCertificate(Registration registration, String[] domainNames, String organization) throws IOException, AcmeException, InterruptedException {
        logger.info("Creating private key");
        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(4096);

        logger.info("Creating certificate request (CSR)");
        CSRBuilder csrb = new CSRBuilder();
        for (String domainName: domainNames) {
            csrb.addDomain(domainName);
        }
        csrb.setOrganization(organization);
        csrb.sign(domainKeyPair);
        byte[] csr = csrb.getEncoded();

        logger.info("Saving certificate request for renewal purposes");
        try (FileWriter fw = new FileWriter("letsencrypt-" + domainNames[0] + "-cert-request.csr")) {
            csrb.write(fw);
        }

        logger.info("Requesting certificate meta..");
        final Certificate certificate = fetchWithRetry(() -> registration.requestCertificate(csr));
        logger.info("Requesting certificate..");
        X509Certificate cert = fetchWithRetry(() -> certificate.download());
        logger.info("Requesting certificate chain..");
        X509Certificate[] chain = fetchWithRetry(() -> certificate.downloadChain());

        logger.info("Saving certificate chain");
        try (FileWriter fw = new FileWriter("letsencrypt-" + domainNames[0] + "-cert-chain.crt")) {
            CertificateUtils.writeX509CertificateChain(fw, cert, chain);
        }

        logger.info("Installing certificate");
        DynamicCertManager.put("letsencrypt-cert-" + domainNames[0], domainKeyPair.getPrivate(), cert, chain);
    }

    private static final String[] SUPPORTED_CHALLENGES = {
            TlsSni01Challenge.TYPE,
            TlsSni02Challenge.TYPE
    };

    private void executeChallenge(String domainName, Challenge challenge) throws IOException, AcmeException, InterruptedException {
        KeyPair sniKeyPair = KeyPairUtils.createKeyPair(2048);
        X509Certificate cert;
        switch (challenge.getType()) {
            case TlsSni01Challenge.TYPE: {
                TlsSni01Challenge c = (TlsSni01Challenge) challenge;
                cert = CertificateUtils.createTlsSniCertificate(sniKeyPair, c.getSubject());
                break;
            }
            case TlsSni02Challenge.TYPE: {
                TlsSni02Challenge c = (TlsSni02Challenge) challenge;
                cert = CertificateUtils.createTlsSni02Certificate(sniKeyPair, c.getSubject(), c.getSanB());
                break;
            }
            default:
                throw new UnsupportedOperationException("Internal error, unsupported challenge type " + challenge.getType());
        }
        final String id = "letsencrypt-challenge-" + domainName;
        try {
            DynamicCertManager.put(id, sniKeyPair.getPrivate(), cert);
            logger.info("Challenge {} prepared, executing..", challenge.getType());
            challenge.trigger();

            fetchWithRetry(new AcmeSupplier<Boolean>() {
                Status reportedStatus = null;

                @Override
                public Boolean get() throws AcmeException {
                    if (challenge.getStatus() != reportedStatus) {
                        logger.info("Challenge status: " + challenge.getStatus());
                        reportedStatus = challenge.getStatus();
                    }
                    if (challenge.getStatus() == Status.VALID || challenge.getStatus() == Status.INVALID) {
                        return true;
                    }
                    challenge.update();
                    return null;
                }
            });
            logger.info("Challenge execution completed with status " + challenge.getStatus());
            if (challenge.getStatus() != Status.VALID) {
                throw new RuntimeException("Challenge " + challenge.getType() + " for " + domainName + " failed with status " + challenge.getStatus());
            }
        } finally {
            DynamicCertManager.remove(id);
            logger.info("Challenge {} cleaned up", challenge.getType());
        }
    }

    private KeyPair getOrCreateAccountKeyPair() throws IOException {
        KeyPair keyPair;
        if (new File(DOMAIN_KEY_PAIR_FILE).exists()) {
            keyPair = read(DOMAIN_KEY_PAIR_FILE, fr -> KeyPairUtils.readKeyPair(fr));
            logger.info("Existing account keypair read from " + DOMAIN_KEY_PAIR_FILE);
        } else {
            //keyPair = KeyPairUtils.createECKeyPair("secp256r1");
            keyPair = KeyPairUtils.createKeyPair(4096);
            write(DOMAIN_KEY_PAIR_FILE, fw -> KeyPairUtils.writeKeyPair(keyPair, fw));
            logger.info("New account keypair written to " + DOMAIN_KEY_PAIR_FILE);
        }
        return keyPair;
    }

    private Registration getOrCreateRegistration(Session session) throws AcmeException, IOException, URISyntaxException {
        // TODO update registration when agreement, contact or others change (save to file what were last used values)
        Registration registration;
        if (new File(DOMAIN_ACCOUNT_LOCATION_FILE).exists()) {
            logger.info("Domain account location file " +  DOMAIN_ACCOUNT_LOCATION_FILE + " exists, using..");
            URI location = new URI(read(DOMAIN_ACCOUNT_LOCATION_FILE, r -> r.readLine()));
            logger.info("Domain account location: " + location);
            registration = Registration.bind(session, location);
            logger.info("Registration successfully bound");
        } else {
            logger.info("No domain account location file, attempting to create new registration");
            RegistrationBuilder builder = new RegistrationBuilder();
            if (CONTACT_EMAIL != null) {
                builder.addContact("mailto:" + CONTACT_EMAIL);
            }
            try {
                registration = builder.create(session);
                logger.info("Registration successfully created");
            } catch (AcmeConflictException e) {
                logger.info("Registration existed, using provided location: " + e.getLocation());
                registration = Registration.bind(session, e.getLocation());
                logger.info("Registration successfully bound");
            }
            final Registration finalRegistration = registration;
            write(DOMAIN_ACCOUNT_LOCATION_FILE, w -> w.write(finalRegistration.getLocation().toASCIIString()));
            logger.info("Domain account location file " +  DOMAIN_ACCOUNT_LOCATION_FILE + " saved");
        }
        return registration;
    }

    public interface Read<T> {
        T read(BufferedReader r) throws IOException;
    }

    private static <T> T read(String file, Read<T> read) throws IOException {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(file), "UTF-8"))) {
            return read.read(r);
        }
    }

    public interface Write {
        void write(Writer w) throws IOException;
    }

    private static void write(String file, Write write) throws IOException {
        try (Writer w = new OutputStreamWriter(new FileOutputStream(file), "UTF-8")) {
            write.write(w);
        }
    }

    public interface AcmeSupplier<T> {
        T get() throws AcmeException;
    }

    <T> T fetchWithRetry(AcmeSupplier<T> supplier) throws InterruptedException, AcmeException {
        while (true) {
            try {
                T t = supplier.get();
                if (t != null) {
                    return t;
                }
                Thread.sleep(3000);
            } catch (AcmeRetryAfterException e) {
                Date retryAfter = e.getRetryAfter();
                long nextSleep = retryAfter.getTime() - System.currentTimeMillis();
                logger.info("Waiting until {} for certificate e.g. {}ms", retryAfter, nextSleep);
                Thread.sleep(nextSleep);
            }
        }
    }

}
