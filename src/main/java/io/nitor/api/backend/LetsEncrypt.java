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

import io.vertx.core.http.HttpServerRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.RegistrationBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeConflictException;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;

public class LetsEncrypt {

    static final String DOMAIN_KEY_PAIR_FILE = "letsencrypt-keypair.pem";
    static final String DOMAIN_ACCOUNT_LOCATION_FILE = "letsencrypt-accountLocation.txt";
    static final String CONTACT_EMAIL = null;
    static final String DOMAIN_NAME = "localhost";

    static final String ACME_SERVER_URI = "acme://letsencrypt.org/staging";

    private static Logger logger = LogManager.getLogger(LetsEncrypt.class);

    public void handle(HttpServerRequest request) {
        try {

        } catch (Exception e) {
            request.response().setStatusCode(500);
            request.response().headers().set("content-type", "text/plain;charset=UTF-8");
            request.response().end(e.getMessage());
        }
    }

    public LetsEncrypt() {
        try {
            KeyPair keyPair = getOrCreateDomainKeyPair();
            Session session = new Session(new URI(ACME_SERVER_URI), keyPair);
            logger.info("Session set up");
            Registration registration = getOrCreateRegistration(session);
            Authorization auth = registration.authorizeDomain(DOMAIN_NAME);
            logger.info("Domain authorized: " + DOMAIN_NAME);
            Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
            if (challenge == null) {
                throw new RuntimeException("Unable to authorize letsencrypt domain; challenge type not available");
            }
            logger.info("Challenge created: " + challenge);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private KeyPair getOrCreateDomainKeyPair() throws IOException {
        KeyPair keyPair;
        if (new File(DOMAIN_KEY_PAIR_FILE).exists()) {
            keyPair = read(DOMAIN_KEY_PAIR_FILE, fr -> KeyPairUtils.readKeyPair(fr));
            logger.info("Existing domain keypair read from " + DOMAIN_KEY_PAIR_FILE);
        } else {
            keyPair = KeyPairUtils.createECKeyPair("secp256r1");
            write(DOMAIN_KEY_PAIR_FILE, fw -> KeyPairUtils.writeKeyPair(keyPair, fw));
            logger.info("New domain keypair written to " + DOMAIN_KEY_PAIR_FILE);
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

}
