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
package io.nitor.vertx.acme4j;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.nitor.vertx.acme4j.AcmeConfig.Account;
import io.nitor.vertx.acme4j.async.AsyncKeyPairUtils;
import io.nitor.vertx.acme4j.util.DynamicCertManager;
import io.nitor.vertx.acme4j.util.DynamicCertManager.CertCombo;
import io.nitor.vertx.acme4j.util.MultiException;
import io.nitor.vertx.acme4j.util.PemLoader;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
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

import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
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
import static java.util.Collections.emptyMap;
import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.stream.Collectors.toList;

public class AcmeManager {

    static final String ACCOUNT_KEY_PAIR_FILE = "account-keypair.pem";
    static final String CERTIFICATE_KEY_PAIR_FILE = "keypair.pem";
    static final String CERTIFICATE_CHAIN_FILE = "certchain.pem";
    static final String DOMAIN_ACCOUNT_LOCATION_FILE = "accountLocation.txt";
    static final String ACCEPTED_TERMS_LOCATION_FILE = "acceptedTermsLocation.txt";
    static final String ACTIVE_CONF_PATH = "active.json";

    //static final String ACME_SERVER_URI = "acme://letsencrypt.org/staging";
    // static final String AGREEMENT_URI = "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf";

    private static Logger logger = LogManager.getLogger(AcmeManager.class);

    private final Vertx vertx;
    private final DynamicCertManager dynamicCertManager;
    private final String dbPath;
    private final AcmeConfigManager configManager = new AcmeConfigManager();
    private AcmeConfig cur;

    enum State { NOT_STARTED, UPDATING, OK, FAILED }
    private State state = State.NOT_STARTED;

    public AcmeManager(Vertx vertx, DynamicCertManager dynamicCertManager, String dbPath) {
        this.vertx = vertx;
        this.dynamicCertManager = dynamicCertManager;
        this.dbPath = dbPath.endsWith("/") ? dbPath : dbPath + '/';
    }

    class AcmeConfigManager {
        public Future<Void> update(final AcmeConfig oldC, final AcmeConfig newC) {
            newC.validate();
            return mapDiff(oldC == null ? new HashMap<>() : oldC.accounts, newC.accounts)
                    .stream()
                    .map((account) -> (Function<Future<Void>, Future<Void>>) prev -> {
                        final AccountManager am = new AccountManager(account.key, account.oldValue, account.newValue);
                        final Future<Void> cur = future();
                        am.updateCached().setHandler(ar1 -> {
                            if (ar1.failed()) {
                                logger.error("Error updating account using cached data", new RuntimeException("For account " + account.key, ar1.cause()));
                                prev.compose(v -> Future.<Void>failedFuture("Some account(s) failed")).setHandler(cur);
                                return;
                            }
                            prev.setHandler(prevResult ->
                                    am.updateOthers().setHandler(ar2 -> {
                                        if (ar2.failed()) {
                                            logger.error("Error updating account", new RuntimeException("For account " + account.key, ar2.cause()));
                                            cur.fail("Some account(s) failed");
                                            return;
                                        }
                                        cur.handle(prevResult);
                            }));
                        });
                        return cur;
                    })
                    .reduce(Function::andThen)
                    .orElse(f -> f)
                    .apply(succeededFuture())
                    .map(v -> {
                        long numDefaultCerts = newC.accounts.entrySet()
                                .stream()
                                .filter(a -> a.getValue().enabled)
                                .flatMap(a -> a.getValue().certificates.entrySet()
                                        .stream()
                                        .filter(e -> e.getValue().enabled && e.getValue().defaultCert)
                                        .map(e -> new SimpleEntry<>(a.getKey(), e.getKey())))
                                .count();
                        if (numDefaultCerts == 0) {
                            dynamicCertManager.setIdOfDefaultAlias(null);
                        }
                        logger.info("Done updating " + newC.accounts.size() + " accounts");
                        return v;
                    });
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
                        return cm.updateCached().recover(describeFailure("For certificate " + certificate.key));
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
                                return cm.updateOthers().recover(describeFailure("For certificate " + certificate.key));
                            });
                    return join(futures);
                });
            });
        }

        private Future<Authorization> getAuthorization(String domain) {
            return (authorizations != null ? succeededFuture(authorizations) : executeBlocking((Future<Map<String, Authorization>> fut) -> {
                logger.info("Fetching authorizations");
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
                        return Integer.MAX_VALUE;
                    }
                }.stream().collect(Collectors.toMap(Authorization::getDomain, t -> t)));
            })).compose(fut -> {
                Authorization authorization = authorizations.get(domain);
                return authorization != null ? succeededFuture(authorization) : executeBlocking((Future<Authorization> fut2) -> {
                    logger.info("Authorizing " + domain);
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
            return future((Future<Boolean> fut) -> vertx.fileSystem().exists(domainAccountLocationFile, fut)).recover(
                    describeFailure("Domain account location file check")).compose((Boolean keyFileExists) -> {
                if (keyFileExists) {
                    logger.info("Domain account location file " + domainAccountLocationFile + " exists, using..");
                    return future((Future<Buffer> fut) -> vertx.fileSystem().readFile(domainAccountLocationFile, fut)).recover(
                            describeFailure("Domain account location file read")).compose(domainAccountLocation -> {
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
                            .recover(describeFailure("Domain account location file write"))
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
                        future((Future<Boolean> fut) -> vertx.fileSystem().exists(acceptedTermsLocationFile, fut)).recover(
                                describeFailure("Accepted terms location file check")).compose(termsFileExists ->
                                !termsFileExists ? succeededFuture(true) :
                                        future((Future<Buffer> fut) -> vertx.fileSystem().readFile(acceptedTermsLocationFile, fut)).recover(
                                                describeFailure("Accepted terms location file read")).map(buf ->
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
                        logger.info("Updating account");
                        try {
                            editableRegistration.commit();
                            future((Future<Void> fut2) -> vertx.fileSystem().writeFile(acceptedTermsLocationFile, buffer(account.acceptedAgreementUrl), fut2))
                                    .recover(describeFailure("Accepted terms location file write"))
                                    .map(registration)
                                    .setHandler(fut);
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
        final String fullCertificateId;
        final AcmeConfig.Certificate oldC;
        final AcmeConfig.Certificate newC;
        final String keyPairFile;
        final String certificateFile;

        public CertificateManager(Registration registration, String accountDbId, int minimumValidityDays, Function<String, Future<Authorization>> getAuthorization, String certificateId, AcmeConfig.Certificate oldC, AcmeConfig.Certificate newC) {
            this.registration = registration;
            this.accountDbId = accountDbId;
            this.minimumValidityDays = minimumValidityDays;
            this.getAuthorization = getAuthorization;
            this.certificateId = certificateId;
            this.fullCertificateId = accountDbId + "-" + certificateId;
            this.oldC = oldC;
            this.newC = newC;
            keyPairFile = dbPath + accountDbId + "-" + certificateId + "-" + CERTIFICATE_KEY_PAIR_FILE;
            certificateFile = dbPath + accountDbId + "-" + certificateId + "-" + CERTIFICATE_CHAIN_FILE;
        }

        public Future<Void> updateCached() {
            if (newC == null) {
                // deregister certificate; certificate destruction should be handled in some other way
                dynamicCertManager.remove(fullCertificateId);
                return succeededFuture();
            }
            if (dynamicCertManager.get(fullCertificateId) != null) {
                // already loaded
                return succeededFuture();
            }
            final Future<Boolean> certificateFileExists = future((Future<Boolean> fut) -> vertx.fileSystem().exists(certificateFile, fut))
                    .recover(describeFailure("Certificate file check"));
            final Future<Boolean> keyPairFileExists = future((Future<Boolean> fut) -> vertx.fileSystem().exists(keyPairFile, fut))
                    .recover(describeFailure("KeyPair file check"));
            return join(asList(certificateFileExists, keyPairFileExists).stream()).compose(x ->
                    succeededFuture(certificateFileExists.result() && keyPairFileExists.result())).compose(filesExist -> {
                if (!filesExist) {
                    logger.info("No existing certificate & KeyPair");
                    // some files missing, can't use cached data
                    return succeededFuture();
                }
                logger.info("Loading existing certificate & KeyPair");
                Future<Buffer> certificateFut = future((Future<Buffer> fut) -> vertx.fileSystem().readFile(certificateFile, fut))
                        .recover(describeFailure("Certificate file read"));
                Future<Buffer> keyPairFut = future((Future<Buffer> fut) -> vertx.fileSystem().readFile(keyPairFile, fut))
                        .recover(describeFailure("KeyPair file read"));
                return join(asList(certificateFut, keyPairFut).stream()).compose(v ->
                        executeBlocking((Future<Void> fut) -> {
                            logger.info("Parsing existing certificate & KeyPair");
                            X509Certificate[] certChain = PemLoader.loadCerts(certificateFut.result());

                            AsyncKeyPairUtils.readKeyPair(vertx, keyPairFut.result()).compose(keyPair -> {
                                // TODO consider filtering subset of hostnames to be served
                                logger.info("Installing existing certificate & KeyPair");
                                dynamicCertManager.put(fullCertificateId, newC.defaultCert, keyPair.getPrivate(), certChain);
                                return Future.<Void>succeededFuture();
                            }).setHandler(fut);
                        }));
            });
        }

        public Future<Void> updateOthers() {
            if (newC == null) {
                return succeededFuture();
            }
            if (oldC != null && oldC.equals(newC)) {
                // certificate is configuration-wise up-to-date
                CertCombo certCombo = dynamicCertManager.get(fullCertificateId);
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
                        return createCertificate(registration, accountDbId, certificateId, keyPairFile, certificateFile, newC.hostnames, newC.organization).map(w -> {
                            logger.info("Certificate successfully activated");
                            return w;
                        });
                    });
        }

        private Future<KeyPair> getOrCreateCertificateKeyPair(String keyPairFile) {
            //keyPairFut = AsyncKeyPairUtils.createECKeyPair(vertx, "secp256r1");
            return getOrCreateKeyPair("certificate", keyPairFile, () -> AsyncKeyPairUtils.createKeyPair(vertx, 4096));
        }

        private Future<Void> createCertificate(Registration registration, String accountDbId, String certificateId, String keyPairFile, String certificateFile, List<String> domainNames, String organization) {
            return getOrCreateCertificateKeyPair(keyPairFile).compose(domainKeyPair -> executeBlocking((Future<Void> fut) -> {
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
                    }).recover(describeFailure("Certificate Request file write")).compose(v -> {
                        logger.info("Requesting certificate meta..");
                        return fetchWithRetry(() -> registration.requestCertificate(csrb.getEncoded()))
                                .recover(describeFailure("Certificate request")).compose(certificate -> {
                            logger.info("Requesting certificate..");
                            return fetchWithRetry(() -> certificate.download())
                                    .recover(describeFailure("Certificate download")).compose(cert -> {
                                logger.info("Requesting certificate chain..");
                                return fetchWithRetry(() -> certificate.downloadChain())
                                        .recover(describeFailure("Certificate chain download")).compose(chain -> {
                                    logger.info("Serializing certificate chain");
                                    return executeBlocking((Future<Buffer> writeCert) -> {
                                        try {
                                            StringWriter certSw = new StringWriter();
                                            CertificateUtils.writeX509CertificateChain(certSw, cert, chain);
                                            writeCert.complete(buffer(certSw.toString()));
                                        } catch (IOException e) {
                                            writeCert.fail(e);
                                        }
                                    }).compose(certBuffer -> {
                                            logger.info("Saving certificate chain");
                                            return future((Future<Void> fut4) -> vertx.fileSystem().writeFile(certificateFile, certBuffer, fut4))
                                                    .recover(describeFailure("Certificate file write")).compose(vv -> {
                                                logger.info("Installing certificate");
                                                dynamicCertManager.put(fullCertificateId, newC.defaultCert, domainKeyPair.getPrivate(), cert, chain);
                                                return Future.<Void>succeededFuture();
                                            });
                                    });
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
            return executeBlocking((Future<String> fut) -> {
                logger.info("Creating challenge keypair");
                try {
                    KeyPair sniKeyPair = KeyPairUtils.createKeyPair(4096);
                    X509Certificate cert;
                    logger.info("Creating challenge certificate");
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
                    logger.info("Installing challenge certificate");
                    dynamicCertManager.put(id, false, sniKeyPair.getPrivate(), cert);
                    logger.info("Challenge {} prepared, executing..", challenge.getType());
                    challenge.trigger();
                    fut.complete(id);
                } catch (Exception e) {
                    fut.fail(e);
                }
            }).compose(id -> {
                return fetchWithRetry(new Callable<Boolean>() {
                    Status reportedStatus = null;

                    @Override
                    public Boolean call() throws Exception {
                        if (challenge.getStatus() != reportedStatus) {
                            logger.info("Challenge status: " + challenge.getStatus());
                            reportedStatus = challenge.getStatus();
                        }
                        if (challenge.getStatus() == Status.VALID || challenge.getStatus() == Status.INVALID) {
                            // final state
                            return true;
                        }
                        challenge.update();
                        return null;
                    }
                }).recover(t -> {
                    dynamicCertManager.remove(id);
                    logger.info("Challenge {} cleaned up", challenge.getType());
                    return failedFuture(t);
                }).compose(s -> {
                    logger.info("Challenge execution completed with status " + challenge.getStatus());
                    dynamicCertManager.remove(id);
                    logger.info("Challenge {} cleaned up", challenge.getType());
                    if (challenge.getStatus() == Status.VALID) {
                        return succeededFuture();
                    }
                    return failedFuture(new RuntimeException("Challenge " + challenge.getType() + " for " + domainName + " failed with status " + challenge.getStatus()));
                });
            });
        }
    }

    private String activeConfigPath() {
        return dbPath + ACTIVE_CONF_PATH;
    }

    /**
     * Start up with previous config, or empty config if no previous config exists.
     *
     * @return A future that can be monitored for completion of startup.
     */
    public Future<Void> start() {
        changeState(State.NOT_STARTED, State.UPDATING);
        return initDb().compose(v -> getActiveConfigFuture().compose(savedConf -> doUpdate(savedConf, savedConf)));
    }

    /**
     * Start up with given config.
     *
     * @return A future that can be monitored for completion of startup.
     */
    public Future<Void> start(AcmeConfig conf) {
        changeState(State.NOT_STARTED, State.UPDATING);
        return initDb().compose(v -> getActiveConfigFuture().compose(savedConf -> doUpdate(savedConf, conf.clone())));
    }

    /**
     * Reconfigure to use given config.
     *
     * @return A future that can be monitored for completion of reconfiguration.
     */
    public Future<Void> reconfigure(AcmeConfig conf) {
        changeState(State.OK, State.UPDATING);
        return doUpdate(cur, conf.clone());
    }

    // TODO if something goes wrong on account level, continue with other accounts before failing
    // TODO likewise for certificate level

    private Future<AcmeConfig> getActiveConfigFuture() {
        String file = activeConfigPath();
        return future((Future<Boolean> fut) -> vertx.fileSystem().exists(file, fut))
                .recover(describeFailure("Error checking previous config " + file))
                .compose(exists ->
                        exists ? readConf(file, "active") : future((Future<AcmeConfig> fut) -> fut.complete(emptyConf())));
    }

    public AcmeConfig emptyConf() {
        AcmeConfig emptyConf = new AcmeConfig();
        emptyConf.accounts = emptyMap();
        return emptyConf;
    }

    private void changeState(State expectedState, State newState) {
        synchronized (AcmeManager.this) {
            if (state != expectedState) {
                throw new IllegalStateException("Wrong state " + state);
            }
            state = newState;
        }
    }

    private Future<Void> doUpdate(AcmeConfig oldConf, AcmeConfig newConf) {
        return configManager.update(oldConf, newConf)
                .compose(v -> {
                    cur = newConf;
                    return writeConf(activeConfigPath(), "active", newConf);
                })
                .map(v -> {
                    synchronized (AcmeManager.this) {
                        state = State.OK;
                    }
                    return v;
                })
                .recover(t -> {
                    synchronized (AcmeManager.this) {
                        state = State.FAILED;
                    }
                    return failedFuture(t);
                });
    }

    private Future<Void> initDb() {
        return future((Future<Void> fut) -> vertx.fileSystem().mkdirs(dbPath, fut))
                .recover(describeFailure("DB directory create"));
    }

    public Future<AcmeConfig> readConf(final String file, final String type) {
        return future((Future<Buffer> fut) -> vertx.fileSystem().readFile(file, fut))
                .recover(describeFailure("Error loading " + type + " config " + file))
                .compose(buf -> executeBlocking(fut -> {
                    try {
                        ObjectMapper objectMapper = new ObjectMapper();
                        AcmeConfig result = objectMapper.readValue(buf.getBytes(), AcmeConfig.class);
                        logger.info(ucFirst(type) + " config read from " + file);
                        fut.complete(result);
                    } catch (IOException e) {
                        fut.fail(new RuntimeException(ucFirst(type) + " config file " + file + " broken", e));
                    }
                }));
    }

    public Future<Void> writeConf(final String file, final String type, final AcmeConfig newConf) {
        return executeBlocking(((Future<Buffer> fut) -> {
            try {
                fut.complete(buffer(new ObjectMapper().writeValueAsBytes(newConf)));
            } catch (JsonProcessingException e) {
                fut.fail(e);
            }
        })).compose(buf -> future((Future<Void> fut) -> vertx.fileSystem().writeFile(file, buf, fut))
                .recover(describeFailure(ucFirst(type) + " config file write"))
                .map(v -> {
                    logger.info(ucFirst(type) + " config written to " + file);
                    return v;
                }));
    }

    private String ucFirst(String s) {
        return s.substring(0, 1).toUpperCase() + s.substring(1);
    }

    private static <K, V> List<MapDiff<K,V>> mapDiff(final Map<K, V> old, final Map<K, V> nev) {
        List<MapDiff<K, V>> res = old.entrySet().stream()
                .map(e -> new MapDiff<>(e.getKey(), e.getValue(), nev.get(e.getKey())))
                .collect(toList());
        List<MapDiff<K, V>> res2 = nev.entrySet().stream()
                .filter(e -> !old.containsKey(e.getKey()))
                .map(e -> new MapDiff<>(e.getKey(), null, e.getValue()))
                .collect(toList());
        res.addAll(res2);
        return res;
    }

    private <T> Function<Throwable, Future<T>> describeFailure(String msg) {
        return t -> failedFuture(new RuntimeException(msg, t));
    }

    Future<KeyPair> getOrCreateKeyPair(String type, final String keyPairFile, final Supplier<Future<KeyPair>> creator) {
        return future((Future<Boolean> fut) -> vertx.fileSystem().exists(keyPairFile, fut))
                .recover(describeFailure("Keypair for " + type + " file check")).compose(keyFileExists -> {
            if (keyFileExists) {
                // file exists
                return future((Future<Buffer> fut) -> vertx.fileSystem().readFile(keyPairFile, fut))
                        .recover(describeFailure("Keypair for " + type + " file read"))
                        .compose(existingKeyFile -> AsyncKeyPairUtils.readKeyPair(vertx, existingKeyFile))
                        .map((KeyPair readKeyPair) -> {
                            logger.info("Existing " + type + " keypair read from " + keyPairFile);
                            return readKeyPair;
                        });
            } else {
                // file doesn't exist
                logger.info("Creating new " + type + " keypair");
                return creator.get().compose(createdKeyPair -> AsyncKeyPairUtils.writeKeyPair(vertx, createdKeyPair)
                        .compose(keyPairSerialized -> future((Future<Void> fut) -> vertx.fileSystem().writeFile(keyPairFile, keyPairSerialized, fut))
                                .recover(describeFailure("Keypar for " + type + " file write")))
                        .map(v -> {
                            logger.info("New " + type + " keypair written to " + keyPairFile);
                            return createdKeyPair;
                        }));
            }
        });
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
            logger.info("Recheck in {}ms @ {}", nextSleep, new Date(System.currentTimeMillis() + nextSleep));
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

    // wait for all futures to finish, discard success values, collect & wrap all exceptions thrown, returned as failed future
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

    // for a stream of callable functions returning futures, execute each in order, waiting for the previous' Future to complete, and returning a future completing when all completes. Aborts on failure, returning failure without executing rest of futures
    static Future<Void> chain(Stream<Supplier<Future<Void>>> stream) {
        return stream.reduce((Supplier<Future<Void>> a, Supplier<Future<Void>> b) -> () -> a.get().compose(v -> b.get()))
                .orElse(() -> succeededFuture())
                .get();
    }

    <T> Future<T> executeBlocking(Handler<Future<T>> blockingHandler) {
        return future((Future<T> fut) -> vertx.executeBlocking(blockingHandler, fut));
    }
}
