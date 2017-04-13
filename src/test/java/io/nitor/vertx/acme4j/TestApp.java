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

import io.nitor.vertx.acme4j.util.DynamicCertManager;
import io.nitor.vertx.acme4j.util.DynamicCertOptions;
import io.nitor.vertx.acme4j.util.SetupHttpServerOptions;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Launcher;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.logging.Logger;

import java.nio.file.Paths;
import java.util.stream.Stream;

import static com.nitorcreations.core.utils.KillProcess.killProcessUsingPort;
import static io.vertx.core.logging.LoggerFactory.getLogger;
import static java.lang.Integer.getInteger;
import static java.lang.System.*;
import static java.nio.file.Files.exists;

public class TestApp extends AbstractVerticle
{
    private static final int listenPort = getInteger("port", 8443);
    private static Logger logger;

    public static void main(String... args) throws Exception {
        setupLogging();
        killProcessUsingPort(listenPort);
        if (getProperty("java.version", "").startsWith("9")) {
            setProperty("io.netty.noKeySetOptimization", "true");
        }
        try {
            Launcher.main(Stream.concat(Stream.of("run", TestApp.class.getName()), Stream.of(args)).toArray(String[]::new));
        } catch (Exception ex) {
            ex.printStackTrace();
            exit(3);
        }
    }

    private static void setupLogging() {
        if (exists(Paths.get("src/test/resources/log4j2.xml"))) {
            setProperty("log4j.configurationFile", "src/test/resources/log4j2.xml");
        }
        setProperty("vertx.logger-delegate-factory-class-name", "io.vertx.core.logging.Log4j2LogDelegateFactory");
        logger = getLogger(TestApp.class);
    }

    @Override
    public void start() {
        vertx.exceptionHandler(e -> {
           logger.error("Fallback exception handler got", e);
        });

        // server side certificates
        DynamicCertOptions dynamicCertOptions = new DynamicCertOptions();
        HttpServerOptions httpServerOptions = SetupHttpServerOptions.createHttpServerOptions(vertx, dynamicCertOptions);

        vertx.createHttpServer(httpServerOptions)
                .requestHandler(this::handle)
                .listen(listenPort);

        DynamicCertManager certManager = new DynamicCertManager(vertx, dynamicCertOptions);

        AcmeManager acmeMgr = new AcmeManager(vertx, certManager, ".acmemanager");
        acmeMgr.readConf("acme.json", "conf")
                .compose(conf -> acmeMgr.start(conf))
                .setHandler(ar -> {
                    if (ar.failed()) {
                        logger.error("AcmeManager start failed", ar.cause());
                        return;
                    }
                    logger.info("AcmeManager start successful");
                });
    }

    void handle(HttpServerRequest req) {
        HttpServerResponse resp = req.response();
        resp.putHeader("strict-transport-security", "max-age=31536000; includeSubDomains");
        resp.putHeader("x-frame-options", "DENY");
        resp.putHeader("content-type", "text/plain; charset=utf-8");
        resp.setStatusCode(200).end("Hello wørld!");
    }
}
