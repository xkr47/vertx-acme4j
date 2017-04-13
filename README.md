# vertx-acme4j
[vert.x](https://github.com/eclipse/vert.x/) adaptation of [acme4j](https://github.com/shred/acme4j) (Let's Encrypt)

Provides a management layer so that you just have to configure the domains you want (and contact email) and the rest is automated (account & certificate creation, installation & renewal).

# Pros (?)
* Supports only tls-sni-01 and tls-sni-02 challenges, which means all challenges happen through the same port 443 as the server itself
* Supports multiple ACME (Let's Encrypt or other) accounts, multiple certificates per account and/or multiple hostnames per certificate
* Enables TLS SNI support in vert.x through custom, dynamically reconfigurable keystore (no listen socket downtime) - you can thus use it for hosting/reverse-proxying multiple TLS-enabled sites behind a single IP with different hostnames and/or certificates
  * you can implement a server that does not even serve a certificate at all unless the client requests a hostname of one of your certificates -> pure IP scanning reveals nothing (assuming reverse lookup of the server IP does not reveal a supported domain)
* Configurable through POJOs or JSON files.

# Cons
* Requires TLS SNI from clients, but seems pretty well supported these days
  * browsers & cURL support it
  * most trouble would probably be related to accessing e.g. REST endpoints over HTTPS from applications e.g. whether they support TLS SNI 
* You can still OPTIONALLY have a default domain selected if SNI not provided (supported) by the client 

# Sample config file

```json
{
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

# tls-sni-01 and tls-sni-02

These challenges work so that a temporary certificate is made for a specific dummy domain. Using TLS SNI, the ACME provider then makes a request to our server on port 443, with the SNI hostname set to the dummy domain. The challenge is then completed when our server responds with the temporary certificate.

Thanks to how SNI works we can still serve our regular domains (assuming you are using the certificates to serve HTTPS traffic) at the same time on the same port. Thanks to the dynamically reconfigurable keystore we can do it in vert.x without interruption to the service of the regular domains.

# Under construction

This code is by no means ready. Don't expect it to work yet. Many scenarios already verified to work.

# Goals and guidelines

* Keep at most one ACME activity going at once, i.e. never attempt to create accounts or certificates or challenges at the same time.
  * It's easier to deal with problems with a serial history of events
  * If you're bringing up a new set of things, they are by definition not in production yet, so time is not that much of an essence
* Bring already existing certificates up as soon as possible regardless of the accessibility of the involved ACME servers
  * At least you get the most important e.g. existing services up and running quickly & regardless of outbound network connectivity
  * Even if the certificates would have expired; better have some service than no service
    * This could perhaps be configurable
* Locally cache data necessary to achieve the above goals
* Database (storing certs and metadata) implementation provided by interface so you can choose between single-machine or clustered implementations or write your own S3/whatnot sync.
