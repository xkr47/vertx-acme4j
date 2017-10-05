# vertx-acme4j
[vert.x](https://github.com/eclipse/vert.x/) integration for [acme4j](https://github.com/shred/acme4j) (Let's Encrypt) with fully automated certificate management/provisioning (account registration, certificate creation, installation & renewal).

Allows you to quickly configure the domains, integrate it into your vert.x / vertx-web application and manage all the HTTPS/TLS/SSL related stuff for you.

# Getting started

Instructions for [getting started](GETTING_STARTED.md) and [API docs](API.md) on separate pages.

# Pros (?)
* Supports only tls-sni-01 and tls-sni-02 challenges, which means all challenges happen through the same port 443 as the server itself; no need to keep port 80 open.
* Supports multiple ACME (Let's Encrypt or other, as supported by [acme4j](https://github.com/shred/acme4j)) accounts, multiple certificates per account and/or multiple hostnames per certificate
* Enables TLS SNI support in vert.x through custom, dynamically reconfigurable keystore
  * you can thus use it for hosting/reverse-proxying multiple services behind a single IP and port while still serving different certificates, selected using SNI hostname.
  * you can implement a server that does not have a default certificate at all -> TLS handshake fails if hostname is not listed in any of the installed certificates -> pure IP scanning reveals nothing (assuming reverse lookup of the server IP does not reveal a supported domain)
  * certificate updates occur without service downtime
* renewals and reattempts of failed renewals occur nightly at configured time
  * configurable how many days in advance new certs are retrieved
* Configurable through POJOs or JSON files.
* While not directly related, works with HTTP/2 given that you have netty-compatible ALPN support enabled through e.g. jetty-alpn, openssl, boringssl etc.

# Cons
* Requires TLS SNI from clients if you a) don't want to have a default certificate or b) clients need to access hostnames of other certificates than the **default certificate**. So if you can put all hostnames that need to be accessible by TLS-SNI-handicapped clients in the default certificate, TLS SNI is NOT required of the clients. Luckily TLS SNI seems pretty well supported by clients these days:
  * browsers & cURL support it
  * most trouble would probably be related to accessing e.g. REST endpoints over HTTPS from applications e.g. whether they support TLS SNI

# Sample config

As JSON file:

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

or same programmatically:

```java
import space.xkr47.vertx.acme4j.AcmeConfig;
import space.xkr47.vertx.acme4j.AcmeConfig.Account;
import space.xkr47.vertx.acme4j.AcmeConfig.Certificate;

import java.time.LocalTime;
import java.util.Arrays;
import java.util.HashMap;

        AcmeConfig config = new AcmeConfig();
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
```

# What is tls-sni-01 and tls-sni-02

ACME ensures that you are indeed in control of the domains you wish to have certificates for by asking you to prove it using one of the available challenges. Various protocols are available to do this. The tls-sni-* ones do it through the same port that the HTTPS/TLS traffic normally occurs for encrypted traffic. This means you don't need any additional firewall/etc configuration. Other challenges use for example port 80 or DNS records for proof. 

In detail, the tls-sni-* challenges work so that a temporary certificate is made for a specific dummy domain. Using TLS SNI, the ACME provider then makes a request to our server on port 443, with the SNI hostname set to the dummy domain. The challenge is then completed when our server responds with the temporary certificate.

Thanks to how SNI works we can still serve our regular domains (assuming you are using the certificates to serve HTTPS traffic) at the same time on the same port. Thanks to the dynamically reconfigurable keystore we can do it in vert.x without interruption to the service of the regular domains.

# Being test-driven on my personal projects

The code is nearing a first release. It's in production use for my personal projects, testing the use of multiple certificates and multiple hostnames per certificate. Creating the first batch of 3 certificates with 8 hostnames took 5 minutes, mostly because of slow generation of new key pairs. (Installing a tool called "haveged" can speed up this and other similar processes like generating ssh keys.)

Documentation is being updated to show how to deploy it in your existing server.

# Getting started

Instructions for [getting started](GETTING_STARTED.md) and [API docs](API.md) on separate pages.

# Project goals and guidelines

* [x] Keep at most one ACME activity going at once, i.e. never attempt to create accounts or certificates or challenges at the same time.
  * It's easier to deal with problems with a serial history of events
  * If you're bringing up a new set of things, they are by definition not in production yet, so time is not that much of an essence
* [x] Bring already existing certificates up as soon as possible regardless of the accessibility of the involved ACME servers
  * At least you get the most important e.g. existing services up and running quickly & regardless of outbound network connectivity
  * [ ] Even if the certificates would have expired; better have some service than no service
    * [ ] This could perhaps be configurable
  * [x] This is done in parallel
* [x] Locally cache data necessary to achieve the above goals
* [ ] Database (storing certs and metadata) implementation provided by interface so you can choose between single-machine or clustered implementations or write your own S3/whatnot sync.
