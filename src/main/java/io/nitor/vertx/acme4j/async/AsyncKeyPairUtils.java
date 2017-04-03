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

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
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
    public static void createKeyPair(Vertx vertx, int keysize, Handler<AsyncResult<KeyPair>> handler) {
        vertx.executeBlocking(fut -> {
            fut.complete(KeyPairUtils.createKeyPair(keysize));
        }, handler);
    }

    public static void readKeyPair(Vertx vertx, Buffer buf, Handler<AsyncResult<KeyPair>> handler) {
        vertx.executeBlocking(fut -> {
            try {
                fut.complete(KeyPairUtils.readKeyPair(new StringReader(buf.toString())));
            } catch (IOException e) {
                fut.fail(e);
            }
        }, handler);
    }

    public static void writeKeyPair(Vertx vertx, KeyPair keypair, Handler<AsyncResult<Buffer>> handler) {
        vertx.executeBlocking(fut -> {
            StringWriter sw = new StringWriter();
            try (JcaPEMWriter jw = new JcaPEMWriter(sw)) {
                jw.writeObject(keypair);
            } catch (IOException e) {
                fut.fail(e);
                return;
            }
            fut.complete(Buffer.buffer(sw.toString()));
        }, handler);
    }
}
