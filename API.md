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

The `DynamicCertManager` class provides an api to AcmeManager for adding and removing certificates dynamically from the listening socket.

Typically DynamicCertManager methods are not used by other instances since the certificates are happily managed by AcmeManager.

### new DynamicCertManager(Vertx, DynamicCertOptions)

Sets up a new DynamicCertManager with the given `Vertx` and `DynamicCertOptions` instances. The given DynamicCertOptions instance is used to push the set of active certificates to use to the TLS socket.

## DynamicCertOptions

The `DynamicCertOptions` class provides a low-level api for switching active certificates for use by DynamicCertManager. DynamicCertOptions implements the necessary interfaces for it to be installed with `HttpServerOptions.setKeyCertOptions()`. 

### new DynamicCertOptions()

Constructs a new `DynamicCertOptions` instance.