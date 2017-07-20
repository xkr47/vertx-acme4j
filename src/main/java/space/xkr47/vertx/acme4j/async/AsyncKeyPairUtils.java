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
package space.xkr47.vertx.acme4j.async;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;

import static io.vertx.core.Future.future;

public class AsyncKeyPairUtils {
    public static Future<KeyPair> createKeyPair(Vertx vertx, int keysize) {
        Future<KeyPair> res = future();
        vertx.executeBlocking(fut -> {
            fut.complete(KeyPairUtils.createKeyPair(keysize));
        }, res);
        return res;
    }

    public static Future<KeyPair> readKeyPair(Vertx vertx, Buffer buf) {
        Future<KeyPair> res = future();
        vertx.executeBlocking(fut -> {
            try {
                fut.complete(KeyPairUtils.readKeyPair(new StringReader(buf.toString())));
            } catch (IOException e) {
                fut.fail(e);
            }
        }, res);
        return res;
    }

    public static Future<Buffer> writeKeyPair(Vertx vertx, KeyPair keyPair) {
        Future<Buffer> res = future();
        vertx.executeBlocking(fut -> {
            try {
                StringWriter sw = new StringWriter();
                KeyPairUtils.writeKeyPair(keyPair, sw);
                fut.complete(Buffer.buffer(sw.toString()));
            } catch (IOException e) {
                fut.fail(e);
            }
        }, res);
        return res;
    }
}
