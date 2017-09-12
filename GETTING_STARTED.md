# Getting started

If you like reading code more than english, look at [TestApp.java](src/test/java/space/xkr47/vertx/acme4j/TestApp.java).

## Update your code

When you create a HTTP-only webserver, you typically do:

```java
        vertx.createHttpServer()
                .requestHandler(myHandler)
                .listen(80);

```

You might also pass an `HttpServerOptions` instance to the `createHttpServer()` call like:

```java
        HttpServerOptions options = new HttpServerOptions()
            .setSomeOption(123);
        vertx.createHttpServer(options)
                .requestHandler(myHandler)
                .listen(80);

```

For HTTPS, an `HttpServerOptions` instance will be required. The minimal "sane" setup required to get vertx-acme4j going looks like this:

```java
        DynamicCertOptions dynamicCertOptions = new DynamicCertOptions(); // ➊

        HttpServerOptions options = new HttpServerOptions()
            .setSsl(true)
            .setKeyCertOptions(dynamicCertOptions) // ➊
            .addEnabledSecureTransportProtocol("TLSv1.2") // ➋
            .addEnabledSecureTransportProtocol("TLSv1.3")
            .setJdkSslEngineOptions(new JdkSSLEngineOptions()) // ➌
            .addEnabledCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") // ➍
            .addEnabledCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
            .addEnabledCipherSuite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
            .addEnabledCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        
        vertx.createHttpServer(options)
                .requestHandler(myHandler)
                .listen(443); // ➎

        DynamicCertManager certManager = new DynamicCertManager(vertx, dynamicCertOptions); // ➏

        AcmeManager acmeMgr = new AcmeManager(vertx, certManager, ".acmemanager"); // ➐
        acmeMgr.readConf("acme.json", "conf")
                .compose(config -> acmeMgr.start(config))
                .setHandler(ar -> {
                    if (ar.failed()) {
                        logger.error("AcmeManager start failed", ar.cause());
                        return;
                    }
                    logger.info("AcmeManager start successful");
                });
```

* ➊ The `DynamicCertOptions` provided by vertx-acme4j makes it possible to change certificates used by vertx without downtime.
* ➋ The transport protocols (TLSv1.2 and 1.3) will enable communication with most devices and disable older versions of the TLS protocol to avoid security issues and potential downgrade attacks.
* ➌ It uses the ssl engine included with the JDK (which doesn't support HTTP/2 out of the box yet as of Java 8).
* ➍ The cipher suite list is a list of secure-enough ciphers, last reviewed early 2017.
* ➎ Often you cannot use this port directly as it typically requires administrator privileges. See later section "Privileged port" for some instructions.
* ➏ The `DynamicCertManager` provides an easy-to-use interface for managing which certificates are currently live in the system. It uses the `DynamicCertOptions` instance to activate the updated configuration whenever it changes.
* ➐ The `AcmeManager`:
    * Accepts AcmeManager configuration and live updates to it
    * Communicates with Let's Encrypt servers, creating and renewing certificates as necessary
    * Keeps cached copies of data locally for quick startup
    * Forwards certificates to `DynamicCertManager` as quickly as possible

In the example the config is loaded from the file "acme.json", which might look like:

```json
{
    "renewalCheckTime": "04:27:11",
    "accounts": {
        "testaccount": {
            "enabled": true,
            "acceptedAgreementUrl": "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf",
            "contactURIs": [
                "mailto:foo@example.com"
            ],
            "minimumValidityDays": 5,
            "providerUrl": "acme://letsencrypt.org/staging",          # remove 'staging' for production CA
            "certificates": {
                "testcert": {
                    "enabled": true,
                    "defaultCert": true,
                    "organization": "My test organization",
                    "hostnames": [
                        "non.existing.blahblah"
                    ]
                }
            }
        }
    }
}
```

You can also put/generate the config in Java code directly:

```java
        AcmeConfig config = new AcmeConfig(); // ➊
        config.renewalCheckTime = LocalTime.of(4,27,11);
        config.accounts = new HashMap<>();
        {
            Account testaccount = new Account();
            config.accounts.put("testaccount", testaccount);
            testaccount.enabled = true;
            testaccount.acceptedAgreementUrl = "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf";
            testaccount.contactURIs = Arrays.asList("mailto:foo@example.com");
            testaccount.minimumValidityDays = 5;
            testaccount.providerUrl = "acme://letsencrypt.org/staging"; // remove 'staging' for production CA 
            testaccount.certificates = new HashMap<>();
            {
                Certificate testcert = new Certificate();
                testaccount.certificates.put("testcert", testcert);
                testcert.enabled = true;
                testcert.defaultCert = true;
                testcert.organization = "My test organization";
                testcert.hostnames = Arrays.asList("non.existing.blahblah");
            }
        }

        AcmeManager acmeMgr = new AcmeManager(vertx, certManager, ".acmemanager");
        acmeMgr.start(config) // ➋
                .setHandler(ar -> {
                    if (ar.failed()) {
                        logger.error("AcmeManager start failed", ar.cause());
                        return;
                    }
                    logger.info("AcmeManager start successful");
                });
```

* ➊ Configuration created manually 
* ➋ and deliered to acmeMgr

## Operation overview

AcmeManager stores & caches credentials and certificates in the directory given to the AcmeManager constructor - in the above examples ".acmemanager".

When you start the app the first time (or you have erased the cache directory e.g. ".acmemanager") it will start up the listening socket and immediately start requesting new certificates from Let's Encrypt. At this point it has no certicates yet so any attempt to access the server will give an error in the client.'

Retrieving the certificates will take some time since it involves several heavy certificate operations perform all the steps involved. The certificate(s) will be installed as soon as they become available. Currently they are retrieved one at a time, so if you have multiple certificates configured, some of them will become available later than others.

When you start the app with cached data available, it will start using previously retrieved certificates immediately, i.e. those that are still part of the configuration. After that it will start updating certificates to match the latest coniguration and implement the necessary changes and/or renew expired certificates.

# Updating configuration

If you want to update the configuration dynamically, it is almost the same as starting the AcmeManager, you just call `reconfigure()` instead of `start()`. For json-based configuration:

```java
        acmeMgr.readConf("acme.json", "conf")
                .compose(conf -> acmeMgr.reconfigure(conf))
                .setHandler(ar -> {
                    if (ar.failed()) {
                        logger.error("AcmeManager reconfiguration failed", ar.cause());
                        return;
                    }
                    logger.info("AcmeManager reconfiguration successful");
                });
```

and for Java-based configuration: 

```java
        AcmeConfig config = new AcmeConfig(); // ➊
        config.renewalCheckTime = LocalTime.of(4,27,11);
        // ...
        acmeMgr.reconfigure(config) // ➋
                .setHandler(ar -> {
                    if (ar.failed()) {
                        logger.error("AcmeManager reconfiguration failed", ar.cause());
                        return;
                    }
                    logger.info("AcmeManager reconfiguration successful");
                });
```

**NOTE!** Currently While a reconfiguration operation (or startup) is in progress, you cannot call `reconfigure()` again until the previous operation has finished. Attempting to do so will throw an exception. *I do plan to change this to just queue the new configuration instead.* 

# Privileged port

Due to the HTTPS port (443) requiring administrator privivleges on Unix systems, you have to choose a method to be able to direct traffic for that port to your web server.

You have at least a few options available to achieve that:
* Run your web server as root. NOT RECOMMENDED; security risk.
* Use firewall rules to redirect traffic to a different port not requiring administrator privileges i.e. port 1024 or higher.
* Use a helper app (like systemd) that can allocate the privileged port as administrator and then deliver the so called socket to your application.
* Use a reverse proxy like apapche/nginx in front of your application. In this case you can forget about using vertx-acme4j however since in that case apache/nginx will have to take care of the Let's Encrypt procedure instead.

## Using firewall rules

In Linux, you can use the following firewall rules to redirect traffic from port 443 to some other port, for example 8443 using the following commands:

    iptables -t nat -A PREROUTING -p tcp --dport 443 -m addrtype --dst-type LOCAL -j REDIRECT --to-ports 8443
    iptables -t nat -A OUTPUT     -p tcp --dport 443 -m addrtype --dst-type LOCAL -j REDIRECT --to-ports 8443

After this all traffic to local port 443 will be redirected to port 8443. So you need to configure your app to listen to port 8443 instead of 443. 

## Using systemd

Use `InheritedChannelSelectorProvider.java` from https://github.com/NitorCreations/nitor-backend/blob/master/src/main/java/io/nitor/api/backend/InheritedChannelSelectorProvider.java and add the following code before vert.x startup. 

```java 
        setProperty("java.nio.channels.spi.Selector Provider", InheritedChannelSelectorProvider.class.getName());
```
