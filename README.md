# vertx-acme4j
[vert.x](https://github.com/eclipse/vert.x/) adaptation of [acme4j](https://github.com/shred/acme4j) (Let's Encrypt)

# Pros (?)
* supports only tls-sni-01 and tls-sni-02 challenges, which means all challenges happen through the same port 443 as the server itself
* supports multiple ACME (Let's Encrypt) accounts, multiple certificates per account and/or multiple hostnames per certificate
* enables TLS SNI support in vert.x through custom, dynamically reconfigurable keystore (no listen socket downtime) - you can thus use it for hosting/reverse-proxying multiple TLS-enabled sites with different hostnames and/or certificates

# Cons
* Requires TLS SNI from clients, but seems pretty well supported these days

# tls-sni-01 and tls-sni-02

These challenges work so that a temporary certificate is made for a specific dummy domain. Using TLS SNI, the ACME provider then makes a request to our server, with the SNI hostname set to the dummy domain. The challenge is then completed when our server responds with the temporary certificate.

Thanks to how SNI works we can serve our regular domains at the same time, and thanks to the dynamically reconfigurable keystore we can do it in vert.x without interruption to the service of the regular domains.

# Under construction

This code is by no means ready. Don't expect it to work yet.
