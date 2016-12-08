package io.nitor.api.backend;

import io.vertx.core.http.HttpServerRequest;
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
            Registration registration = getOrCreateRegistration(session);
            Authorization auth = registration.authorizeDomain(DOMAIN_NAME);
            Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
            if (challenge == null) {
                throw new RuntimeException("Unable to authorize letsencrypt domain; challenge type not available");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private KeyPair getOrCreateDomainKeyPair() throws IOException {
        KeyPair keyPair;
        if (new File(DOMAIN_KEY_PAIR_FILE).exists()) {
            keyPair = read(DOMAIN_KEY_PAIR_FILE, fr -> KeyPairUtils.readKeyPair(fr));
        } else {
            keyPair = KeyPairUtils.createECKeyPair("secp256r1");
            write(DOMAIN_KEY_PAIR_FILE, fw -> KeyPairUtils.writeKeyPair(keyPair, fw));
        }
        return keyPair;
    }

    private Registration getOrCreateRegistration(Session session) throws AcmeException, IOException, URISyntaxException {
        // TODO update registration when agreement, contact or others change (save to file what were last used values)
        Registration registration;
        if (new File(DOMAIN_ACCOUNT_LOCATION_FILE).exists()) {
            registration = Registration.bind(session, new URI(read(DOMAIN_ACCOUNT_LOCATION_FILE, r -> r.readLine())));
        } else {
            RegistrationBuilder builder = new RegistrationBuilder();
            if (CONTACT_EMAIL != null) {
                builder.addContact("mailto:" + CONTACT_EMAIL);
            }
            try {
                registration = builder.create(session);
            } catch (AcmeConflictException e) {
                registration = Registration.bind(session, e.getLocation());
            }
            final Registration finalRegistration = registration;
            write(DOMAIN_ACCOUNT_LOCATION_FILE, w -> w.write(finalRegistration.getLocation().toASCIIString()));
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
