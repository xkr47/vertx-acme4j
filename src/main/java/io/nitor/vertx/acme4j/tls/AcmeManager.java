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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.nitor.vertx.acme4j.async.AsyncKeyPairUtils;
import io.nitor.vertx.acme4j.tls.AcmeConfig.Account;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
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
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;

import static io.vertx.core.Future.failedFuture;
import static io.vertx.core.Future.succeededFuture;

public class AcmeManager {

    static final String DOMAIN_KEY_PAIR_FILE = "keypair.pem";
    static final String DOMAIN_ACCOUNT_LOCATION_FILE = "accountLocation.txt";
    static final String ACTIVE_CONF_PATH = "active.json";
    //static final String CONTACT_EMAIL = null;
    //static final String[] DOMAIN_NAMES = {"a139189489518.example.org"};
    //static final String ORGANIZATION = "The Example Organization";

    //static final String ACME_SERVER_URI = "acme://letsencrypt.org/staging";

    // static final String AGREEMENT_URI = "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf";

    private static Logger logger = LogManager.getLogger(AcmeManager.class);

    private final Vertx vertx;
    private final DynamicCertManager dynamicCertManager;
    private final String dbPath;
    private final AcmeConfigManager configManager = new AcmeConfigManager();
    private AcmeConfig cur;

    public AcmeManager(Vertx vertx, DynamicCertManager dynamicCertManager, String dbPath) {
        this.vertx = vertx;
        this.dynamicCertManager = dynamicCertManager;
        this.dbPath = dbPath.endsWith("/") ? dbPath : dbPath + '/';
        //vertx.executeBlocking();
    }

    class AcmeConfigManager {
        public void update(AcmeConfig oldC, AcmeConfig newC) {
            newC.validate();
            final AccountManager am = new AccountManager();
            mapDiff(oldC == null ? new HashMap<>() : oldC.accounts, newC.accounts,
                    (accountId, oldA, newA) -> eh(()-> am.update(accountId, oldA, newA), "account " + accountId));
        }
    }

    class AccountManager {
        public void update(String accountId, Account oldA, Account newA) {
            final CertificateManager cm = new CertificateManager();
            String oldAccountDbId = accountDbIdFor(accountId, oldA);
            String newAccountDbId = accountDbIdFor(accountId, newA);
            if (newA == null || !newAccountDbId.equals(oldAccountDbId)) {
                // deregister all certificates for this account; account destruction should be handled in some other way
                oldA.certificates.entrySet().forEach(e -> eh(() -> cm.update(null, accountId, e.getKey(), e.getValue(), null), "certificate " + e.getKey()));
                if (newA == null) {
                    return;
                }
                oldA = null;
            }

            try {
                KeyPair accountKeyPair = getOrCreateAccountKeyPair(newAccountDbId); // TODO
                Session session = new Session(new URI(newA.providerUrl), accountKeyPair);
                logger.info("Session set up");
                Registration registration = getOrCreateRegistration(newAccountDbId, newA, session);

                try {
                    updateCerts(registration, newAccountDbId, cm, oldA, newA);
                } catch (RuntimeException e) {
                    if (!(e.getCause() instanceof AcmeUnauthorizedException)) {
                        throw e;
                    }

                    updateCerts(registration, newAccountDbId, cm, oldA, newA);
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (URISyntaxException e) {
                e.printStackTrace();
            } catch (AcmeException e) {
                e.printStackTrace();
            }
        }

        private void updateCerts(Registration registration, String newAccountDbId, CertificateManager cm, Account oldA, Account newA) {
            mapDiff(oldA == null ? new HashMap<>() : oldA.certificates, newA.certificates,
                    (certificateId, oldC, newC) -> eh(() -> cm.update(registration, newAccountDbId, certificateId, oldC, newC), "certificate " + certificateId));
        }

        private String accountDbIdFor(String accountId, Account account) {
            try {
                return account == null ? null : accountId + '-' + URLEncoder.encode(account.providerUrl, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
        }

        private void getOrCreateAccountKeyPair(String accountDbId, Handler<AsyncResult<KeyPair>> handler) throws IOException {
            final String domainKeyPairFile = dbPath + accountDbId + '-' + DOMAIN_KEY_PAIR_FILE;
            vertx.fileSystem().exists(domainKeyPairFile, (AsyncResult<Boolean> keyFileExists) -> {
                if (keyFileExists.failed()) {
                    // file check failed
                    handler.handle(failedFuture(keyFileExists.cause()));
                    return;
                }
                if (keyFileExists.result()) {
                    // file exists
                    vertx.fileSystem().readFile(domainKeyPairFile, existingKeyFile -> {
                        if (existingKeyFile.failed()) {
                            handler.handle(failedFuture(existingKeyFile.cause()));
                            return;
                        }
                        AsyncKeyPairUtils.readKeyPair(vertx, existingKeyFile.result(), readKeyPair -> {
                            if (readKeyPair.succeeded()) {
                                logger.info("Existing account keypair read from " + domainKeyPairFile);
                            }
                            handler.handle(readKeyPair);
                        });
                    });
                } else {
                    // file doesn't exist
                    AsyncKeyPairUtils.createKeyPair(vertx, 4096, createdKeyPair -> {
                    //keyPairFut = AsyncKeyPairUtils.createECKeyPair(vertx, "secp256r1");
                        if (createdKeyPair.failed()) {
                            handler.handle(failedFuture(createdKeyPair.cause()));
                            return;
                        }
                        AsyncKeyPairUtils.writeKeyPair(vertx, createdKeyPair.result(), keyPairSerialized -> {
                            if (keyPairSerialized.failed()) {
                                handler.handle(failedFuture(keyPairSerialized.cause()));
                                return;
                            }
                            vertx.fileSystem().writeFile(domainKeyPairFile, keyPairSerialized.result(), ar3 -> {
                                if (ar3.failed()) {
                                    handler.handle(failedFuture(ar3.cause()));
                                    return;
                                }
                                logger.info("New account keypair written to " + domainKeyPairFile);
                                handler.handle(succeededFuture(createdKeyPair.result()));
                            });
                        });
                    });
                }
            });
        }

        private Registration getOrCreateRegistration(String accountDbId, Account account, Session session) throws AcmeException, IOException, URISyntaxException {
            // TODO update registration when agreement, contact or others change (save to file what were last used values)
            Registration registration;
            String domainAccountLocationFile = dbPath + accountDbId + '-' + DOMAIN_ACCOUNT_LOCATION_FILE;
            boolean created = false;
            String[] contactURIs = account.contactURIs == null ? new String[0] : account.contactURIs;
            if (new File(domainAccountLocationFile).exists()) {
                logger.info("Domain account location file " + domainAccountLocationFile + " exists, using..");
                URI location = new URI(read(domainAccountLocationFile, r -> r.readLine()));
                logger.info("Domain account location: " + location);
                registration = Registration.bind(session, location);
                logger.info("Registration successfully bound");
            } else {
                logger.info("No domain account location file, attempting to create new registration");
                RegistrationBuilder builder = new RegistrationBuilder();
                for (String uri : contactURIs) {
                    builder.addContact(uri);
                }
                try {
                    registration = builder.create(session);
                    created = true;
                    logger.info("Registration successfully created");
                } catch (AcmeConflictException e) {
                    logger.info("Registration existed, using provided location: " + e.getLocation());
                    registration = Registration.bind(session, e.getLocation());
                    logger.info("Registration successfully bound");
                }
                final Registration finalRegistration = registration;
                write(domainAccountLocationFile, w -> w.write(finalRegistration.getLocation().toASCIIString()));
                logger.info("Domain account location file " + domainAccountLocationFile + " saved");
            }
            /*
            boolean contactsChanged = !created && !registration.getContacts().equals(asList(account.contactURIs).stream().map(this::toURI).collect(Collectors.toList()));
            boolean agreementChanged = created || !registration.getAgreement().equals(toURI(account.acceptedAgreementUrl));
            if (contactsChanged || agreementChanged) {
                Registration.EditableRegistration editableRegistration = registration.modify();
                List<URI> editableContacts = editableRegistration.getContacts();
                editableContacts.clear();
                for (String uri : contactURIs) {
                    editableContacts.add(toURI(uri));
                }
                editableRegistration.setAgreement(toURI(account.acceptedAgreementUrl));
                editableRegistration.commit();
            }
            */
            return registration;
        }
    }

    class CertificateManager {
        public void update(Registration registration, String accountDbId, String certificateId, AcmeConfig.Certificate oldC, AcmeConfig.Certificate newC) throws AcmeException, IOException, InterruptedException {
            if (newC == null) {
                // deregister certificate; certificate destruction should be handled in some other way
                dynamicCertManager.remove(certificateId);
            }

            String privateKeyFile = dbPath + accountDbId + "-" + certificateId + "-key.pem";
            String certificateFile = dbPath + accountDbId + "-" + certificateId + "-certchain.pem";

            if (vertx.fileSystem().existsBlocking(certificateFile) && vertx.fileSystem().existsBlocking(privateKeyFile)) {
                X509Certificate[] certChain = PemLoader.loadCerts(vertx.fileSystem().readFileBlocking(certificateFile));
                PrivateKey privateKey = PemLoader.loadPrivateKey(vertx.fileSystem().readFileBlocking(privateKeyFile));
                // TODO
            }

            logger.info("Domains to authorize: {}", newC.hostnames);
            for (String domainName : newC.hostnames) {
                logger.info("Authorizing domain {}", domainName);
                Authorization auth;
                //try {
                    auth = registration.authorizeDomain(domainName);
                    /*
                } catch (AcmeUnauthorizedException e) {
                    if (registration.getAgreement().equals(AGREEMENT_URI)) {
                        logger.info("Agreeing to " + AGREEMENT_URI);
                        registration.modify().setAgreement(new URI(AGREEMENT_URI)).commit();
                        auth = registration.authorizeDomain(domainName);
                    } else {
                        throw new RuntimeException("You need to agree to the Subscriber Agreement at: " + registration.getAgreement(), e);
                    }
                }
                */
                logger.info("Domain {} authorized, status {}", domainName, auth.getStatus());
                if (auth.getStatus() == Status.VALID) continue; // TODO what statuses really?
                if (true) continue;
                logger.info("Challenge combinations supported: " + auth.getCombinations());
                Collection<Challenge> combination = auth.findCombination(SUPPORTED_CHALLENGES);
                logger.info("Challenges to complete: " + combination);
                for (Challenge challenge : combination) {
                    executeChallenge(domainName, challenge);
                }
                logger.info("Domain {} successfully associated with account", domainName);
            }
            logger.info("All domains successfully associated with account");
            createCertificate(registration, accountDbId, certificateId, privateKeyFile, certificateFile, newC.hostnames, newC.organization);
            logger.info("Certificate successfully activated. All done.");
        }


        public void writePrivateKey(PrivateKey key, Writer w) throws IOException {
            try (JcaPEMWriter jw = new JcaPEMWriter(w)) {
                jw.writeObject(key);
            }
        }

        private void createCertificate(Registration registration, String accountDbId, String certificateId, String privateKeyFile, String certificateFile, List<String> domainNames, String organization) throws IOException, AcmeException, InterruptedException {
            logger.info("Creating private key");
            KeyPair domainKeyPair = KeyPairUtils.createKeyPair(4096);
            write(privateKeyFile, w -> writePrivateKey(domainKeyPair.getPrivate(), w));

            logger.info("Creating certificate request (CSR)");
            CSRBuilder csrb = new CSRBuilder();
            for (String domainName : domainNames) {
                csrb.addDomain(domainName);
            }
            csrb.setOrganization(organization);
            csrb.sign(domainKeyPair);
            byte[] csr = csrb.getEncoded();

            logger.info("Saving certificate request for renewal purposes");
            try (FileWriter fw = new FileWriter(dbPath + accountDbId + "-" + certificateId + "-cert-request.csr")) {
                csrb.write(fw);
            }

            logger.info("Requesting certificate meta..");
            final Certificate certificate = fetchWithRetry(() -> registration.requestCertificate(csr));
            logger.info("Requesting certificate..");
            X509Certificate cert = fetchWithRetry(() -> certificate.download());
            logger.info("Requesting certificate chain..");
            X509Certificate[] chain = fetchWithRetry(() -> certificate.downloadChain());

            logger.info("Saving certificate chain");
            try (FileWriter fw = new FileWriter(certificateFile)) {
                CertificateUtils.writeX509CertificateChain(fw, cert, chain);
            }

            logger.info("Installing certificate");
            dynamicCertManager.put("letsencrypt-cert-" + certificateId, domainKeyPair.getPrivate(), cert, chain);
        }

        private final String[] SUPPORTED_CHALLENGES = {
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
                dynamicCertManager.put(id, sniKeyPair.getPrivate(), cert);
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
                dynamicCertManager.remove(id);
                logger.info("Challenge {} cleaned up", challenge.getType());
            }
        }
    }

    private String activeConfigPath() {
        return dbPath + ACTIVE_CONF_PATH;
    }

    public void start(Handler<AsyncResult<Void>> startArh) {
        vertx.fileSystem().readFile(activeConfigPath(), fileAr -> {
            if (fileAr.failed()) {
                startArh.handle(failedFuture(fileAr.cause()));
                return;
            }
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                startWithConfig(objectMapper.readValue(fileAr.result().getBytes(), AcmeConfig.class), startArh);
            } catch (IOException e) {
                startArh.handle(failedFuture(e));
            }
        });
    }

    private synchronized void startWithConfig(AcmeConfig conf, Handler<AsyncResult<Void>> startArh) {
        configManager.update(null, conf);
        cur = conf;
        startArh.handle(succeededFuture());
    }

    public synchronized void reconfigure(AcmeConfig conf, Handler<AsyncResult<Void>> completionHandler) {
        if (cur == null) {
            throw new IllegalStateException("Not completed startup yet. Forgot to call start()?");
        }
        configManager.update(cur, conf);
        cur = conf.clone();
        /*
        for (boolean validate : new boolean[] { true, false }) {
            root.getJsonArray("accounts").stream().map(JsonObject.class::cast)
                    .forEach(account ->
                            reconfigureAccount(account, validate)
                    );
        }
        */
    }

    private static <K, V> void mapDiff(Map<K, V> old, Map<K, V> nev, MapDiffHandler<K, V> handler) {
        old.entrySet().forEach(e -> {
            handler.handle(e.getKey(), e.getValue(), nev.get(e.getKey()));
        });
        nev.entrySet().forEach(e -> {
            if (!old.containsKey(e.getKey())) {
                handler.handle(e.getKey(), null, e.getValue());
            }
        });
    }

    /*
        private void reconfigureAccount(JsonObject account, boolean validate) {
            String accountId = account.getString("id");
            if (accountId == null) {
                throw new IllegalArgumentException("Found account without id");
            }
            try {
                String provider = account.getString("provider");
                if (provider == null) {
                    throw new IllegalArgumentException("Must specify provider url");
                }
                String acceptedAgreement = account.getString("acceptedAgreement");
                account.getJsonArray("certificates").stream().map(JsonObject.class::cast)
                        .forEach(certificate ->
                                reconfigureCertificate(accountId, certificate, validate)
                        );
            } catch (Exception e) {
                throw new RuntimeException("For account " + accountId);
            }
        }

        private boolean reconfigureCertificate(String accountId, JsonObject certificate, boolean validate) {
            String certificateId = certificate.getString("id");
            if (certificateId == null) {
                throw new IllegalArgumentException("Found certificate without id");
            }
            try {
                String organization = certificate.getString("organization");
                List<String> hostnames = certificate.getJsonArray("hostnames").stream().map(String.class::cast)
                        .distinct()
                        .collect(Collectors.toList());
                if (hostnames.isEmpty()) {
                    throw new IllegalArgumentException("Must specify at least one hostname");
                }

            } catch (Exception e) {
                throw new RuntimeException("For certificate " +  certificateId);
            }
        }
    */


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

    @FunctionalInterface
    public interface MapDiffHandler<K, V> {
        void handle(K key, V old, V nev);
    }

    @FunctionalInterface
    public interface CheckedProcedure {
        void call() throws Exception;
    }

    static void eh(CheckedProcedure c, String idDescription) {
        try {
            c.call();
        } catch (Exception e) {
            throw new RuntimeException("While handling " + idDescription, e);
        }
    }
}
