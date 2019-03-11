# API docs

## AcmeManager

The `AcmeManager` class is the main engine of this project. Create an instance of it to manage all your accounts, certificates and hostnames.

### new AcmeManager(Vertx, DynamicCertManager, String dbPath)

The `DynamicCertManager` instance is provided by you and is used to deploy & undeploy the temporary certificates needed to verify your domains. The `dbPath` is a relative or absolute path to a directory where you want AcmeManager to store its internal state between startups. The contents of that directory should be backed up regularly.

### Future<Void> start()

Initiates startup of the AcmeManager instance, restoring whatever configuration was active during last time it was run, or an empty config if none.

The returned `Future` can be monitored to see when startup has completed or if there was a problem during startup.

### Future<Void> start(AcmeConfig)

Initiates startup of the AcmeManager instance, using to the given configuration. Any matching accounts and certificates created previously by AcmeManager are reused as much as possible for quick startup and then any necessary updates are implemented to match the given configuration.

The returned `Future` can be monitored to see when startup has completed or if there was a problem during startup.

### Future<Void> reconfigure(AcmeConfig)

Initiates reconfiguration of the AcmeManager instance, using to the given configuration. Any matching accounts and certificates created previously by AcmeManager are reused as much as possible and then any necessary updates are implemented to match the given configuration.

The returned `Future` can be monitored to see when reconfiguration has completed or if there was a problem during reconfiguration.

### Future<AcmeConfig> readConf(String file, String type)

Initiates reading of a JSON file from the given path and returns a `Future` that delivers the parsed configuration, or an error if reading failed.

The "type" argument is a human-readable string that describes which config file is being read. Used for logging purposes. Example: "default", "user", "fallback".

### Future<Void> writeConf(String file, String type, AcmeConfig)

Intitiates serialization of the given configuration to JSON and writing it to the given file.

The returned `Future` can be monitored to see when writing has completed or if there was a problem in the process.

## DynamicCertManager

The `DynamicCertManager` class provides an api for adding and removing TLS certificates dynamically from a listening socket. In this project it is used by AcmeManager but you can also use it as a standalone class if you are not interested in the services of AcmeManager - for example for implementing non-SNI handshakes using your own or even 3rd party software.

DynamicCertManager uses the vert.x logging api in INFO level to report changes implemented.

### new DynamicCertManager(Vertx, DynamicCertOptions)

Sets up a new DynamicCertManager with the given `Vertx` and `DynamicCertOptions` instances.

The DynamicCertManager provides the high-level api for managing certificates, while the DynamicCertOptions is the one doing the low-level work of pushing them to the listening TLS socket. You are not meant to operate on the DynamicCertOptions yourself, just pass it to the listening socket and DynamicCertManager takes care of the rest.

The DynamicCertManager provides an api similar to a Map, but with a few different put() methods for different use-cases. A user-specified `id` is used as key in the map - it is needed just so you can later update/remove the certificate from the map. There is also the concept of a "default" certificate. You can choose one certificate to be the "default" certificate that is presented to clients that do NOT support/include SNI in the TLS handshake. You can also choose not to have a default certificate, in which case non-SNI requests will fail the TLS handshake. The latter comes with a few pros and cons:

* + people scanning the internet for hosts by IP won't find anything on your site if they don't know your hostnames. Of course if a reverse lookup on the server IP reveals one of the hostnames, some might be able to access that one.
* - clients not supporting SNI will not be able to communicate

Browsers and cURL do support SNI, but older clients and programming libraries might not. To support those, you will need to choose a default certificate, and that certificate needs to cover (at least) all the hostnames that you want to access with clients without SNI.

### void setIdOfDefaultAlias(String id)

Sets the ID of the certificate that should be the default. Passing null removes the default, if any. No validation is done on the id - if no certificates currently match then no certificate will be "default", however if a certificate is later added with this id, it will become the default.

If you are also intending to install/update the certificate for that id as well, you can pass `true` as the `defaultCert` argument of put(), in which case it has the same effect as calling this method separately for that id.

### String getIdOfDefaultAlias()

Returns the id of the default certificate. Null if no default certificate is configured. Please note that even if this method returns a non-null value, in case there is no certificate installed with this id then it has the effect of not having a default certificate. If you need to know, call `get()` with the returned id and see if you get a non-null result.

### void put(String id, boolean setAsDefault, java.security.PrivateKey privateKey, java.security.cert.Certificate[] certificateWithChain)

Install a new certificate with the given id. `certificateWithChain` must contain the full chain of certificates. If `setAsDefault` is true, the end result will be as if `setIdOfDefaultAlias(id)` had also been called in the same transaction. This gives the silly feature that if you first call `setIdOfDefaultAlias("main");` and then `put("main", false, ....);` then the certificate will still become default, because it was already configured to be so. Thus passing `false` to `setAsDefault` merely means "do not touch the default setting".

The effective certificate to install must be the first in the array of certificates.

When the method returns, the given certificate is immediately serving requests (at sockets using the associated DynamicCertOptions instance).

### void put(String id, boolean setAsDefault, java.security.PrivateKey privateKey, java.security.cert.Certificate certificate, java.security.cert.Certificate... chain)

This is just a convenience version of the above in case you have the certificate available separately from the chain.

### void put(CertCombo certCombo, boolean setAsDefault)

This is just another way to install certificates. It allows you to use the same CertCombo data structure with `put()` that `get()` returns.

### CertCombo get(String id)

Retrieves the certificate chain and private key installed using the given id.

### void remove(String id)

Immediately removes the certificate installed using the given id. Future handshakes for hostnames covered by those certificates will fail.

### static Certificate[] merge(Certificate cert, Certificate[] chain)

Utility function to merge a certificate with its chain.

## DynamicCertOptions

The `DynamicCertOptions` class provides a low-level api for switching active certificates for use by DynamicCertManager. DynamicCertOptions implements the necessary interfaces for it to be installed with `HttpServerOptions.setKeyCertOptions()`. 

### new DynamicCertOptions()

Constructs a new `DynamicCertOptions` instance.
