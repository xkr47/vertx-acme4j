/**
 * Copyright 2016-2017 Nitor Creations Oy
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

import io.netty.handler.codec.http.HttpResponseStatus;
import io.nitor.api.backend.auth.SetupAzureAdConnectAuth;
import io.nitor.api.backend.auth.SetupOpenIdConnectAuth;
import io.nitor.api.backend.auth.SimpleConfigAuthProvider;
import io.nitor.api.backend.proxy.Proxy.ProxyException;
import io.nitor.api.backend.proxy.SetupProxy;
import io.nitor.api.backend.session.CookieSessionHandler;
import io.nitor.api.backend.tls.SetupHttpServerOptions;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.AuthHandler;
import io.vertx.ext.web.handler.BasicAuthHandler;
import io.vertx.ext.web.handler.StaticHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLPeerUnverifiedException;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.stream.Stream;

import static com.nitorcreations.core.utils.KillProcess.killProcessUsingPort;
import static java.lang.Integer.getInteger;
import static java.lang.System.exit;
import static java.lang.System.getProperty;
import static java.lang.System.setProperty;
import static java.nio.file.Files.exists;
import static java.util.concurrent.TimeUnit.MINUTES;

public class NitorBackend extends AbstractVerticle
{
    private static final int listenPort = getInteger("port", 8443);
    private static Logger logger;

    public static void main(String... args) throws Exception {
        setupLogging();
        setProperty("java.nio.channels.spi.SelectorProvider", InheritedChannelSelectorProvider.class.getName());
        if (!InheritedChannelSelectorProvider.hasInheritedChannel()) {
            killProcessUsingPort(listenPort);
        }
        if (getProperty("java.version", "").startsWith("9")) {
            setProperty("io.netty.noKeySetOptimization", "true");
        }
        try {
            PropertiesLauncher.main(Stream.concat(Stream.of("run", NitorBackend.class.getName()), Stream.of(args)).toArray(String[]::new));
        } catch (Exception ex) {
            ex.printStackTrace();
            exit(3);
        }
    }

    private static void setupLogging() {
        if (exists(Paths.get("log4j2.xml"))) {
            setProperty("log4j.configurationFile", "log4j2.xml");
        }
        setProperty("java.util.logging.manager", "org.apache.logging.log4j.jul.LogManager");
        setProperty("vertx.logger-delegate-factory-class-name", "io.vertx.core.logging.Log4j2LogDelegateFactory");
        logger = LogManager.getLogger(NitorBackend.class);
    }

    @Override
    public void start() {
        vertx.exceptionHandler(e -> {
           logger.error("Fallback exception handler got", e);
        });

        HttpServerOptions httpServerOptions = SetupHttpServerOptions.createHttpServerOptions(config());

        Router router = Router.router(vertx);

        router.route().handler(new AccessLogHandler()::handle);
        router.route().handler(routingContext -> {
            HttpServerResponse resp = routingContext.response();
            resp.putHeader("strict-transport-security", "max-age=31536000; includeSubDomains");
            resp.putHeader("x-frame-options", "DENY");
            routingContext.next();
        });
        router.get("/healthCheck").handler(routingContext -> {
           routingContext.response().setStatusCode(200).end();
        });
        router.get("/certCheck").handler(routingContext -> {
            String resp;
            try {
                resp = "Certs: " + Arrays.toString(routingContext.request().peerCertificateChain());
            } catch (SSLPeerUnverifiedException e) {
                resp = "No client certs available:" + e.getMessage();
            }
            routingContext.response().setChunked(true).write(resp).end();
        });

        LetsEncrypt letsEncrypt = new LetsEncrypt();
        router.get("/.well-known").handler(routingContext -> letsEncrypt.handle(routingContext.request()));

        JsonObject clientAuth = config().getJsonObject("clientAuth");
        if (clientAuth != null) {
            if (null != clientAuth.getString("clientChain")) {
                router.route(clientAuth.getString("path", "/*")).handler(routingContext -> {
                    try {
                        routingContext.request().peerCertificateChain();
                        routingContext.next();
                    } catch (SSLPeerUnverifiedException e) {
                        routingContext.response().setStatusCode(HttpResponseStatus.FORBIDDEN.code());
                        routingContext.response().end();
                        logger.info("Rejected request that was missing valid client certificate from ip {}: {}", routingContext.request().remoteAddress(), e.getMessage());
                    }
                });
            }
        }

        String publicURI = config().getString("publicURI", "https://localhost:" + listenPort);
        if (publicURI.endsWith("/")) {
            publicURI = publicURI.substring(0, publicURI.length() - 1);
        }

        JsonObject oidcAuth = config().getJsonObject("oidcAuth");
        if (oidcAuth != null) {
            SetupOpenIdConnectAuth.setupOpenIdConnect(oidcAuth, router, vertx, publicURI);
        }

        JsonObject adAuth = config().getJsonObject("adAuth");
        if (adAuth != null) {
            JsonObject sessionConf = config().getJsonObject("session", new JsonObject());
            CookieSessionHandler sessionHandler = new CookieSessionHandler(sessionConf);
            SetupAzureAdConnectAuth.setupAzureAd(adAuth, router, vertx, publicURI, sessionHandler);
        }

        JsonObject basicAuth = config().getJsonObject("basicAuth");
        if (basicAuth != null) {
            AuthHandler basicAuthHandler = BasicAuthHandler.create(new SimpleConfigAuthProvider(basicAuth.getJsonObject("users")), basicAuth.getString("realm", "nitor"));
            router.route(basicAuth.getString("path", "/*")).handler(basicAuthHandler);
        }

        JsonArray proxyConf = config().getJsonArray("proxy");
        if (proxyConf != null) {
            proxyConf.forEach(conf -> SetupProxy.setupProxy(vertx, router, (JsonObject) conf, httpServerOptions));
        }

        JsonArray staticConf = config().getJsonArray("static");
        if (staticConf != null) {
            staticConf.forEach(c -> {
                JsonObject conf = (JsonObject) c;
                router.route(conf.getString("path")).handler(
                        StaticHandler.create()
                                .setFilesReadOnly(conf.getBoolean("readOnly", true))
                                .setAllowRootFileSystemAccess(true)
                                .setWebRoot(conf.getString("dir", "."))
                                .setCacheEntryTimeout(conf.getInteger("cacheTimeout", (int) MINUTES.toSeconds(30)))
                );
            });
        }

        router.route().failureHandler(routingContext -> {
            String error = "ERROR";
            int statusCode = routingContext.statusCode();
            Throwable t = routingContext.failure();
            logger.info("Handling failure statusCode=" + statusCode, t);
            if (routingContext.response().ended()) {
                return;
            }
            if (routingContext.response().headWritten()) {
                routingContext.response().end();
                routingContext.request().connection().close();
                return;
            }
            if (t != null) {
                if (t instanceof ProxyException) {
                    statusCode = ((ProxyException) t).statusCode;
                }
                error = "ERROR: " + t.toString();
            }
            routingContext.response().setStatusCode(statusCode != -1 ? statusCode : 500);
            routingContext.response().headers().set("Content-Type", "text/plain; charset=UTF-8");
            routingContext.response().headers().set("Content-Length", Integer.toString(error.length()));
            routingContext.response().end(error);
        });

        vertx.createHttpServer(httpServerOptions)
                .requestHandler(router::accept)
                .listen(listenPort);
    }

}
