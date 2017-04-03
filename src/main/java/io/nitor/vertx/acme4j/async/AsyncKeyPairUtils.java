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
package io.nitor.vertx.acme4j.async;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;

public class AsyncKeyPairUtils {
    public static Future<KeyPair> createKeyPair(Vertx vertx, int keysize) {
        Future<KeyPair> res = Future.future();
        vertx.executeBlocking(fut -> {
            fut.complete(KeyPairUtils.createKeyPair(keysize));
        }, res);
        return res;
    }

    public static Future<KeyPair> readKeyPair(Vertx vertx, Buffer buf) {
        Future res = Future.future();
        vertx.executeBlocking(fut -> {
            try (PEMParser parser = new PEMParser(new StringReader(buf.toString()))) {
                PEMKeyPair keyPair = (PEMKeyPair) parser.readObject();
                new JcaPEMKeyConverter().getKeyPair(keyPair);
            } catch (PEMException ex) {
                fut.fail(new IOException("Invalid PEM file", ex));
            } catch (IOException ex) {
                fut.fail(ex);
            }
        }, res);
        return res;
    }

    public static Future<Buffer> writeKeyPair(Vertx vertx, KeyPair keypair) {
        Future res = Future.future();
        vertx.executeBlocking(fut -> {
            StringWriter sw = new StringWriter();
            try (JcaPEMWriter jw = new JcaPEMWriter(sw)) {
                jw.writeObject(keypair);
            } catch (IOException e) {
                fut.fail(e);
                return;
            }
            fut.complete(Buffer.buffer(sw.toString()));
        }, res);
        return res;
    }
}
