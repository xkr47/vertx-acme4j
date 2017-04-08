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
import io.nitor.vertx.acme4j.tls.DynamicCertManager.CertCombo;
import io.vertx.core.*;
import io.vertx.core.buffer.Buffer;
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
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.CertificateUtils;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static io.vertx.core.Future.*;
import static io.vertx.core.buffer.Buffer.buffer;
import static java.lang.System.currentTimeMillis;
import static java.util.Arrays.asList;
import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.stream.Collectors.toList;

public class AcmeManager {

    static final String ACCOUNT_KEY_PAIR_FILE = "account-keypair.pem";
    static final String CERTIFICATE_KEY_PAIR_FILE = "certificate-keypair.pem";
    static final String DOMAIN_ACCOUNT_LOCATION_FILE = "accountLocation.txt";
    static final String ACCEPTED_TERMS_LOCATION_FILE = "acceptedTermsLocation.txt";
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
    }

    class AcmeConfigManager {
        public void update(final AcmeConfig oldC, final AcmeConfig newC, final Handler<AsyncResult<Void>> doneHandler) {
            newC.validate();
            mapDiff(oldC == null ? new HashMap<>() : oldC.accounts, newC.accounts)
                    .stream()
                    .map((account) -> (Function<Future<Void>, Future<Void>>) prev -> {
                        final AccountManager am = new AccountManager(account.key, account.oldValue, account.newValue);
                        final Future<Void> cur = future();
                        am.updateCached().setHandler(ar1 -> {
                            if (ar1.failed()) {
                                logger.error("While handling account " + account.key, ar1.cause());
                                prev.setHandler(cur);
                                return;
                            }
                            prev.setHandler(prevResult -> {
                                am.updateOthers().setHandler(ar2 -> {
                                    if (ar2.failed()) {
                                        logger.error("While handling account " + account.key, ar2.cause());
                                        cur.fail("Some account(s) failed");
                                        return;
                                    }
                                    cur.handle(prevResult);
                                });
                            });
                        });
                        return cur;
                    })
                    .reduce(Function::andThen)
                    .orElse(f -> f)
                    .apply(succeededFuture())
                    .setHandler(doneHandler);
        }
    }

    class AccountManager {
        final String accountId;
        final Account oldAOrig;
        final Account newAOrig;
        final String oldAccountDbId;
        final String newAccountDbId;
        Map<String, Authorization> authorizations;
        Registration registration;

        public AccountManager(String accountId, Account oldA, Account newA) {
            this.accountId = accountId;
            this.oldAOrig = oldA;
            this.newAOrig = newA;
            oldAccountDbId = accountDbIdFor(accountId, oldA);
            newAccountDbId = accountDbIdFor(accountId, newA);
        }

        public Future<Void> updateCached() {
            if (newAOrig == null || !newAccountDbId.equals(oldAccountDbId)) {
                // deregister all certificates for old account; account destruction should be handled in some other way
                return updateCached2(oldAccountDbId, oldAOrig, null)
                        // register all certificates for new account
                        .compose(v -> updateCached2(newAccountDbId, null, newAOrig));
            } else {
                // update all certificates for same account
                return updateCached2(newAccountDbId, oldAOrig, newAOrig);
            }
        }

        private Future<Void> updateCached2(String accountDbId, Account oldA, Account newA) {
            Map<String, AcmeConfig.Certificate> oldCs = oldA == null ? new HashMap<>() : oldA.certificates;
            Map<String, AcmeConfig.Certificate> newCs = newA == null ? new HashMap<>() : newA.certificates;
            Stream<Future<Void>> futures = mapDiff(oldCs, newCs)
                    .stream()
                    .map((certificate) -> {
                        final CertificateManager cm = new CertificateManager(null, accountDbId, newA.minimumValidityDays, null, certificate.key, certificate.oldValue, certificate.newValue);
                        return cm.updateCached().recover(t -> failedFuture(new RuntimeException("For certificate " + certificate.key, t)));
                    });
            return join(futures);
        }

        public Future<Void> updateOthers() {
            if (newAOrig == null || !newAccountDbId.equals(oldAccountDbId)) {
                /*// deregister all certificates for old account; account destruction should be handled in some other way
                updateOthers2(oldAccountDbId, oldAOrig, null, ar -> {
                    */
                    // register all certificates for new account
                    return updateOthers2(null);
                /*
                });
                 */
            } else {
                // update all certificates for same account
                return updateOthers2(oldAOrig);
            }
        }

        public Future<Void> updateOthers2(Account oldA) {
            return getOrCreateAccountKeyPair(newAccountDbId).compose(accountKeyPair -> {
                Session session;
                try {
                    session = new Session(new URI(newAOrig.providerUrl), accountKeyPair);
                } catch (URISyntaxException e) {
                    return failedFuture(e);
                }
                logger.info(accountId + ": Session set up");
                return getOrCreateRegistration(newAccountDbId, newAOrig, session).compose(registration -> {
                    this.registration = registration;
                    Map<String, AcmeConfig.Certificate> oldCs = oldA == null ? new HashMap<>() : oldA.certificates;
                    Map<String, AcmeConfig.Certificate> newCs = newAOrig == null ? new HashMap<>() : newAOrig.certificates;
                    Stream<Future<Void>> futures = mapDiff(oldCs, newCs)
                            .stream()
                            .map((certificate) -> {
                                final CertificateManager cm = new CertificateManager(registration, newAccountDbId, newAOrig.minimumValidityDays, this::getAuthorization, certificate.key, certificate.oldValue, certificate.newValue);
                                return cm.updateOthers().recover(t -> failedFuture(new RuntimeException("For certificate " + certificate.key, t)));
                            });
                    return join(futures);
                });
            });
        }

        private Future<Authorization> getAuthorization(String domain) {
            return (authorizations != null ? succeededFuture(authorizations) : executeBlocking((Future<Map<String, Authorization>> fut) -> {
                fut.complete(authorizations = new AbstractCollection<Authorization>() {
                    @Override
                    public Iterator<Authorization> iterator() {
                        try {
                            return registration.getAuthorizations();
                        } catch (AcmeException e) {
                            throw new RuntimeException("Problem fetching existing authorizations", e);
                        }
                    }

                    @Override
                    public int size() {
                        throw new UnsupportedOperationException();
                    }
                }.stream().collect(Collectors.toMap(Authorization::getDomain, t -> t)));
            })).compose(fut -> {
                Authorization authorization = authorizations.get(domain);
                return authorization != null ? succeededFuture(authorization) : executeBlocking((Future<Authorization> fut2) -> {
                    try {
                        fut2.complete(registration.authorizeDomain(domain));
                    } catch (AcmeException e) {
                        fut2.fail(new RuntimeException("Problem creating new authorization", e));
                    }
                });
            });
        }

        private String accountDbIdFor(String accountId, Account account) {
            try {
                return account == null ? null : accountId + '-' + URLEncoder.encode(account.providerUrl, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
        }

        private Future<KeyPair> getOrCreateAccountKeyPair(String accountDbId) {
            String accountKeyPairFile = dbPath + accountDbId + '-' + ACCOUNT_KEY_PAIR_FILE;
            return getOrCreateKeyPair("account", accountKeyPairFile, () -> AsyncKeyPairUtils.createKeyPair(vertx, 4096));
            //keyPairFut = AsyncKeyPairUtils.createECKeyPair(vertx, "secp256r1");
        }

        private Future<Registration> getOrCreateRegistration(String accountDbId, Account account, Session session) {
            // TODO update registration when agreement, contact or others change (save to file what were last used values)
            String domainAccountLocationFile = dbPath + accountDbId + '-' + DOMAIN_ACCOUNT_LOCATION_FILE;
            final List<String> contactURIs = account.contactURIs == null ? Collections.emptyList() : account.contactURIs;
            return future((Future<Boolean> fut) -> vertx.fileSystem().exists(domainAccountLocationFile, fut)).compose((Boolean keyFileExists) -> {
                if (keyFileExists) {
                    logger.info("Domain account location file " + domainAccountLocationFile + " exists, using..");
                    return future((Future<Buffer> fut) -> vertx.fileSystem().readFile(domainAccountLocationFile, fut)).compose(domainAccountLocation -> {
                        String locationStr = domainAccountLocation.toString();
                        logger.info("Domain account location: " + locationStr);
                        URI location;
                        try {
                            location = new URI(locationStr);
                        } catch (URISyntaxException e) {
                            return failedFuture(e);
                        }
                        Registration registration = Registration.bind(session, location);
                        logger.info("Registration successfully bound");
                        return succeededFuture(new SimpleEntry<>(registration, false));
                    });
                } else {
                    return executeBlocking((Future<Entry<Registration, Boolean>> createFut) -> {
                        logger.info("No domain account location file, attempting to create new registration");
                        RegistrationBuilder builder = new RegistrationBuilder();
                        for (String uri : contactURIs) {
                            builder.addContact(uri);
                        }
                        boolean created = false;
                        Registration registration;
                        try {
                            registration = builder.create(session);
                            created = true;
                            logger.info("Registration successfully created");
                        } catch (AcmeConflictException e) {
                            logger.info("Registration existed, using provided location: " + e.getLocation());
                            registration = Registration.bind(session, e.getLocation());
                            logger.info("Registration successfully bound");
                        } catch (AcmeException e) {
                            createFut.fail(e);
                            return;
                        }
                        createFut.complete(new SimpleEntry<>(registration, created));
                    }).compose(creation -> future((Future<Void> fut) ->
                            vertx.fileSystem().writeFile(domainAccountLocationFile, buffer(creation.getKey().getLocation().toASCIIString()), fut))
                            .map(v -> {
                                logger.info("Domain account location file " + domainAccountLocationFile + " saved");
                                return creation;
                            }));
                }
            }).compose(registrationCombo -> {
                final Registration registration = registrationCombo.getKey();
                final boolean created = registrationCombo.getValue();
                String acceptedTermsLocationFile = dbPath + accountDbId + '-' + ACCEPTED_TERMS_LOCATION_FILE;
                boolean contactsChanged = !created && !registration.getContacts().equals(account.contactURIs.stream().map(URI::create).collect(Collectors.toList()));
                return (contactsChanged || created ? succeededFuture(true) :
                        future((Future<Boolean> fut) -> vertx.fileSystem().exists(acceptedTermsLocationFile, fut)).compose(termsFileExists ->
                                !termsFileExists ? succeededFuture(true) :
                                        future((Future<Buffer> fut) -> vertx.fileSystem().readFile(acceptedTermsLocationFile, fut)).map(buf ->
                                                !buf.toString().equals(account.acceptedAgreementUrl)))
                ).compose(registrationPropsChanged -> {
                    if (!registrationPropsChanged) {
                        return succeededFuture(registration);
                    }
                    Registration.EditableRegistration editableRegistration = registration.modify();
                    List<URI> editableContacts = editableRegistration.getContacts();
                    editableContacts.clear();
                    for (String uri : contactURIs) {
                        editableContacts.add(URI.create(uri));
                    }
                    editableRegistration.setAgreement(URI.create(account.acceptedAgreementUrl));
                    return executeBlocking(fut -> {
                        try {
                            editableRegistration.commit();
                            vertx.fileSystem().writeFile(acceptedTermsLocationFile, buffer(account.acceptedAgreementUrl), ar ->
                                    fut.handle(ar.map(registration)));
                        } catch (AcmeException e) {
                            fut.fail(e);
                        }
                    });
                });
            });
        }
    }

    class CertificateManager {
        final Registration registration;
        final String accountDbId;
        final int minimumValidityDays;
        final Function<String, Future<Authorization>> getAuthorization;
        final String certificateId;
        final AcmeConfig.Certificate oldC;
        final AcmeConfig.Certificate newC;
        final String privateKeyFile;
        final String certificateFile;

        public CertificateManager(Registration registration, String accountDbId, int minimumValidityDays, Function<String, Future<Authorization>> getAuthorization, String certificateId, AcmeConfig.Certificate oldC, AcmeConfig.Certificate newC) {
            this.registration = registration;
            this.accountDbId = accountDbId;
            this.minimumValidityDays = minimumValidityDays;
            this.getAuthorization = getAuthorization;
            this.certificateId = certificateId;
            this.oldC = oldC;
            this.newC = newC;
            privateKeyFile = dbPath + accountDbId + "-" + certificateId + "-key.pem";
            certificateFile = dbPath + accountDbId + "-" + certificateId + "-certchain.pem";
        }

        public Future<Void> updateCached() {
            if (newC == null) {
                // deregister certificate; certificate destruction should be handled in some other way
                dynamicCertManager.remove(certificateId);
                return succeededFuture();
            }
            if (dynamicCertManager.get(certificateId) != null) {
                // already loaded
                return succeededFuture();
            }
            final Future<Boolean> certificateFileExists = future((Future<Boolean> fut) -> vertx.fileSystem().exists(certificateFile, fut));
            final Future<Boolean> privateKeyFileExists = future((Future<Boolean> fut) -> vertx.fileSystem().exists(privateKeyFile, fut));
            return join(asList(certificateFileExists, privateKeyFileExists).stream()).compose(x ->
                    succeededFuture(certificateFileExists.result() && privateKeyFileExists.result())).compose(filesExist -> {
                if (!filesExist) {
                    // some files missing, can't use cached data
                    return succeededFuture();
                }
                Future<Buffer> certificateFut = future((Future<Buffer> fut) -> vertx.fileSystem().readFile(certificateFile, fut));
                Future<Buffer> privateKeyFut = future((Future<Buffer> fut) -> vertx.fileSystem().readFile(privateKeyFile, fut));
                return executeBlocking((Future<Void> fut) -> {
                    X509Certificate[] certChain = PemLoader.loadCerts(certificateFut.result());
                    PrivateKey privateKey = PemLoader.loadPrivateKey(privateKeyFut.result());
                    // TODO consider filtering subset of hostnames to be served
                    dynamicCertManager.put(certificateId, privateKey, certChain);
                    fut.complete();
                });
            });
        }

        public Future<Void> updateOthers() {
            // has the config changed
            // is the certificate still valid
            // are the authorizations still valid
            if (newC == null) {
                return succeededFuture();
            }
            if (oldC.equals(newC)) {
                // certificate is configuration-wise up-to-date
                CertCombo certCombo = dynamicCertManager.get(certificateId);
                if (certCombo != null) {
                    X509Certificate cert = (X509Certificate) certCombo.certWithChain[0];
                    try {
                        cert.checkValidity(new Date(currentTimeMillis() + DAYS.toMillis(minimumValidityDays)));
                        return succeededFuture();
                    } catch (CertificateNotYetValidException e) {
                        return failedFuture(new RuntimeException("Unexpected certificate validity period", e));
                    } catch (CertificateExpiredException e) {
                        // not valid anymore in <minimumValidityDays> days, request new
                    }
                }
            }
            logger.info("Domains to authorize: {}", newC.hostnames);
            return chain(newC.hostnames
                    .stream()
                    .map((domainName) -> (Supplier<Future<Void>>) () -> {
                        logger.info("Authorizing domain {}", domainName);
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
                        return getAuthorization.apply(domainName).compose(auth ->
                                executeBlocking((Future<Status> fut) -> fut.complete(auth.getStatus())).compose(status -> {
                                    logger.info("Domain {} authorization status: {}", domainName, status);
                                    if (status == Status.VALID)
                                        return succeededFuture(); // TODO what statuses really?
                                    logger.info("Challenge combinations supported: " + auth.getCombinations());
                                    Collection<Challenge> combination = auth.findCombination(SUPPORTED_CHALLENGES);
                                    logger.info("Challenges to complete: " + combination);
                                    return chain(combination.stream().map(challenge -> (Supplier<Future<Void>>) () ->
                                            executeChallenge(domainName, challenge))).map(v -> {
                                        logger.info("Domain {} successfully associated with account", domainName);
                                        return null;
                                    });
                                })).<Void>mapEmpty();
                    }))
                    .compose(v -> {
                        logger.info("All domains successfully authorized by account");
                        return createCertificate(registration, accountDbId, certificateId, privateKeyFile, certificateFile, newC.hostnames, newC.organization).map(w -> {
                            logger.info("Certificate successfully activated. All done.");
                            return w;
                        });
                    });
        }

        public void writePrivateKey(PrivateKey key, Writer w) throws IOException {
            try (JcaPEMWriter jw = new JcaPEMWriter(w)) {
                jw.writeObject(key);
            }
        }

        private Future<KeyPair> getOrCreateCertificateKeyPair() {
            String certificateKeyPairFile = dbPath + accountDbId + '-' + certificateId + "-" + CERTIFICATE_KEY_PAIR_FILE;
            //keyPairFut = AsyncKeyPairUtils.createECKeyPair(vertx, "secp256r1");
            return getOrCreateKeyPair("certificate", certificateKeyPairFile, () -> AsyncKeyPairUtils.createKeyPair(vertx, 4096));
        }

        private Future<Void> createCertificate(Registration registration, String accountDbId, String certificateId, String privateKeyFile, String certificateFile, List<String> domainNames, String organization) {
            logger.info("Creating private key");
            return getOrCreateCertificateKeyPair().compose(domainKeyPair -> executeBlocking((Future<Void> fut) -> {
                // write(privateKeyFile, w -> writePrivateKey(domainKeyPair.getPrivate(), w));

                final CSRBuilder csrb;
                try {
                    logger.info("Creating certificate request (CSR)");
                    csrb = new CSRBuilder();
                    for (String domainName : domainNames) {
                        csrb.addDomain(domainName);
                    }
                    csrb.setOrganization(organization);
                    csrb.sign(domainKeyPair);

                    logger.info("Saving certificate request for renewal purposes");
                    StringWriter sw = new StringWriter();
                    csrb.write(sw);
                    final Buffer buffer = buffer(sw.toString());

                    future((Future<Void> fut2) -> {
                        String csrFile = dbPath + accountDbId + "-" + certificateId + "-cert-request.csr";
                        vertx.fileSystem().writeFile(csrFile, buffer, fut2);
                    }).compose(v -> {
                        logger.info("Requesting certificate meta..");
                        return fetchWithRetry(() -> registration.requestCertificate(csrb.getEncoded())).compose(certificate -> {
                            logger.info("Requesting certificate..");
                            return fetchWithRetry(() -> certificate.download()).compose(cert -> {
                                logger.info("Requesting certificate chain..");
                                return fetchWithRetry(() -> certificate.downloadChain()).compose(chain -> {
                                    logger.info("Saving certificate chain");
                                    return executeBlocking((Future<Buffer> writeCert) -> {
                                        try {
                                            StringWriter certSw = new StringWriter();
                                            CertificateUtils.writeX509CertificateChain(certSw, cert, chain);
                                            writeCert.complete(buffer(certSw.toString()));
                                        } catch (IOException e) {
                                            writeCert.fail(e);
                                        }
                                    }).compose(certBuffer ->
                                            future((Future<Void> fut4) -> vertx.fileSystem().writeFile(certificateFile, certBuffer, fut4)).compose(vv -> {
                                                logger.info("Installing certificate");
                                                dynamicCertManager.put("letsencrypt-cert-" + certificateId, domainKeyPair.getPrivate(), cert, chain);
                                                return Future.<Void>succeededFuture();
                                            }));
                                });
                            });
                        });
                    }).setHandler(fut);
                } catch (IOException e) {
                    fut.fail(e);
                    return;
                }
            }));
        }

        private final String[] SUPPORTED_CHALLENGES = {
                TlsSni01Challenge.TYPE,
                TlsSni02Challenge.TYPE
        };

        private Future<Void> executeChallenge(String domainName, Challenge challenge) {
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

                fetchWithRetry(new Callable<Boolean>() {
                    Status reportedStatus = null;

                    @Override
                    public Boolean call() throws Exception {
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
        if (state != State.NOT_STARTED) {
            throw new IllegalStateException("Already started");
        }
        synchronized (AcmeManager.this) {
            state = State.UPDATING;
        }
        vertx.fileSystem().readFile(activeConfigPath(), fileAr -> {
            if (fileAr.failed()) {
                synchronized (AcmeManager.this) {
                    state = State.FAILED;
                }
                startArh.handle(fileAr.mapEmpty());
                return;
            }
            vertx.<AcmeConfig>executeBlocking(fut -> {
                try {
                    ObjectMapper objectMapper = new ObjectMapper();
                    fut.complete(objectMapper.readValue(fileAr.result().getBytes(), AcmeConfig.class));
                } catch (IOException e) {
                    fut.fail(e);
                }
            }, readConf -> {
                if (readConf.failed()) {
                    synchronized (AcmeManager.this) {
                        state = State.FAILED;
                    }
                    startArh.handle(readConf.mapEmpty());
                    return;
                }
                startWithConfig(readConf.result(), ar -> {
                    synchronized (AcmeManager.this) {
                        state = ar.failed() ? State.FAILED : State.OK;
                    }
                    startArh.handle(ar);
                });
            });
        });
    }

    enum State { NOT_STARTED, UPDATING, OK, FAILED }

    private State state = State.NOT_STARTED;

    private void startWithConfig(AcmeConfig conf, Handler<AsyncResult<Void>> startArh) {
        configManager.update(null, conf, ar -> {
            if (ar.succeeded()) {
                cur = conf;
            }
            synchronized (AcmeManager.this) {
                state = State.OK;
            }
            startArh.handle(ar);
        });
    }

    public void reconfigure(AcmeConfig conf, Handler<AsyncResult<Void>> completionHandler) {
        synchronized (AcmeManager.this) {
            if (state != State.OK) {
                throw new IllegalStateException("Wrong state " + state);
            }
            state = State.UPDATING;
        }
        final AcmeConfig conf2 = conf.clone();
        // TODO if something goes wrong on account level, continue with other accounts before failing
        // TODO likewise for certificate level
        configManager.update(cur, conf2, ar -> {
            if (ar.succeeded()) {
                cur = conf2;
            }
            synchronized (AcmeManager.this) {
                state = State.OK;
            }
            completionHandler.handle(ar);
        });
    }

    private static <K, V> List<MapDiff<K,V>> mapDiff(final Map<K, V> old, final Map<K, V> nev) {
        List<MapDiff<K, V>> res = old.entrySet().stream()
                .map(e -> new MapDiff<>(e.getKey(), e.getValue(), nev.get(e.getKey())))
                .collect(toList());
        List<MapDiff<K, V>> res2 = nev.entrySet().stream()
                .filter(e -> !old.containsKey(e.getKey()))
                .map(e -> new MapDiff<>(e.getKey(), null, e.getValue()))
                .collect(toList());
        res.addAll(res);
        return res;
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

    Future<KeyPair> getOrCreateKeyPair(String type, final String keyPairFile, final Supplier<Future<KeyPair>> creator) {
        return future((Future<Boolean> fut) -> vertx.fileSystem().exists(keyPairFile, fut)).compose(keyFileExists -> {
            if (keyFileExists) {
                // file exists
                return future((Future<Buffer> fut) -> vertx.fileSystem().readFile(keyPairFile, fut))
                        .compose(existingKeyFile -> AsyncKeyPairUtils.readKeyPair(vertx, existingKeyFile))
                        .map((KeyPair readKeyPair) -> {
                            logger.info("Existing " + type + " keypair read from " + keyPairFile);
                            return readKeyPair;
                        });
            } else {
                // file doesn't exist
                return creator.get().compose(createdKeyPair -> AsyncKeyPairUtils.writeKeyPair(vertx, createdKeyPair)
                        .compose(keyPairSerialized -> future((Future<Void> fut) -> vertx.fileSystem().writeFile(keyPairFile, keyPairSerialized, fut)))
                        .map(v -> {
                            logger.info("New " + type + " keypair written to " + keyPairFile);
                            return createdKeyPair;
                        }));
            }
        });
    }

    public interface Write {
        void write(Writer w) throws IOException;
    }

    private static void write(String file, Write write) throws IOException {
        try (Writer w = new OutputStreamWriter(new FileOutputStream(file), "UTF-8")) {
            write.write(w);
        }
    }

    <T> Future<T> fetchWithRetry(Callable<T> blockingHandler) {
        return future((Future<T> fut) -> fetchWithRetry(blockingHandler, fut));
    }

    <T> void fetchWithRetry(Callable<T> blockingHandler, Future<T> done) {
        vertx.executeBlocking((Future<T> fut) -> {
            try {
                fut.complete(blockingHandler.call());
            } catch (Exception e) {
                fut.fail(e);
            }
        }, ar -> {
            if (ar.failed() && !(ar.cause() instanceof AcmeRetryAfterException)) {
                done.fail(ar.cause());
                return;
            }
            if (ar.succeeded() && ar.result() != null) {
                done.complete(ar.result());
                return;
            }
            long nextSleep = ar.succeeded() ? 3000 : ((AcmeRetryAfterException) ar.cause()).getRetryAfter().getTime() - currentTimeMillis();
            logger.info("Recheck in {}ms", nextSleep);
            vertx.setTimer(nextSleep, timerId -> fetchWithRetry(blockingHandler, done));
        });
    }

    public static class MapDiff<K, V> {
        public final K key;
        public final V oldValue;
        public final V newValue;
        public MapDiff(K key, V oldValue, V newValue) {
            this.key = key;
            this.oldValue = oldValue;
            this.newValue = newValue;
        }
    }

    static <T> Future<Void> join(Stream<Future<T>> futures) {
        return futures
                .map((fut) -> (Function<Future<List<Throwable>>, Future<List<Throwable>>>) prev ->
                        prev.compose(throwables -> {
                            Future<List<Throwable>> res = future();
                            fut.setHandler(futRes -> {
                                if (futRes.failed()) {
                                    throwables.add(futRes.cause());
                                }
                                res.complete(throwables);
                            });
                            return res;
                        }))
                .reduce(Function::andThen)
                .orElse(f -> f)
                .apply(succeededFuture(new ArrayList<>()))
                .compose(throwables -> {
                    if (!throwables.isEmpty()) {
                        return failedFuture(MultiException.wrapIfNeeded(throwables));
                    }
                    return succeededFuture();
                });
    }

    static Future<Void> chain(Stream<Supplier<Future<Void>>> stream) {
        return stream.reduce((Supplier<Future<Void>> a, Supplier<Future<Void>> b) -> () -> a.get().compose(v -> b.get()))
                .orElse(() -> succeededFuture())
                .get();
    }

    <T> Future<T> executeBlocking(Handler<Future<T>> blockingHandler) {
        return future((Future<T> fut) -> vertx.executeBlocking(blockingHandler, fut));
    }
}
