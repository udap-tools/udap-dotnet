# Running examples

To get the most out of the example project run them all together.  To make that easier [Project Tye](https://github.com/dotnet/tye) can spin all the services up together and give you a portal to see what is running on which port.  Tye is not required and you can start each service by hand.

### dotnet tye

```txt
dotnet tool install -g Microsoft.Tye --version "0.12.0-*" --add-source https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet6/nuget/v3/index.json
```

### Start the services

The following will start the services and watch for changes.  Think hot reload.  When you change a .cs file the service will be recompiled and restarted.

```txt
tye run --watch
```

### Docker

Disclaimer: only tested on Windows running a Linux images.

An alternative ```tye.yaml``` file called ```tye.docker.yaml``` has been created for launching the following as Docker images.

- FhirLabsApi
- Udap.Auth.Server
- Udap.Identity.Provider
- Udap.Identity.Provider.2

The following two are running locally.  

- UdapEd.Server
- Udap.Certificate.Server

Run Tye using the Docker technique with the following command.

```txt
tye run tye.docker.yaml
```

There is no watch option on this one.  The Docker images are release builds, similar to how you would deploy Docker images into production where the ```tye run --watch``` technique is similar to launching docker from Visual Studio where it mounts local volumes and can debug.  

:spiral_notepad: Note: The docker run args include ```--env=ASPNETCORE_ENVIRONMENT=Development```.  This will let it pick ```appsettings.Development.json```.  This is important because configuration for running locally with certificates generated for testing are available.

## Certificates for testing

Remember to run the tests in Udap.PKI.Generator

It will generate a PKI including the host.docker.intenal.pfx SSL Certificate and SurefhirCA.cer.  This is critical to enable SSL to work for Docker to Docker communications and Docker to desktop communications.  The test that generates this is ```MakeCaWithIntermediateUdapAndSSLForDefaultCommunity```.  While it will generate many others the SSL certificates are the only important certificates for running locally.  They should be copied automatically to the projects.  Each project already has the configuration in ```appsettings.json``` to load this certificate.

```json
"Kestrel": {
  "Certificates": {
    "Default": {
      "Path": "host.docker.internal.pfx",
      "Password": "udap-test"
    }
  }
}```

:spiral_notepad: Note: On Windows some Docker Desktop instances will map the local IP and host.docker.internal host name automatically.  My desktop used to do it then stopped an now works again.  So you may have to manually set it.  Example:

```txt
# Added by Docker Desktop
192.168.86.40 host.docker.internal
192.168.86.40 gateway.docker.internal
# To allow the same kube context to work on the host and the container:
127.0.0.1 kubernetes.docker.internal
# End of section
```

:spiral_notepad: Note: The host.docker.internal.pfx file is created withe both ```localhost``` and ```host.docker.internal``` in the DNS SAN X509 Extension.  This allows the cert to work like the typical ASP.NET Test certificate and lets Docker find other services.  Of course the SureFhirCA.cer anchor certificate must be installed in the trust stores of Docker and Windows.  For Windows the ```MakeCaWithIntermediateUdapAndSSLForDefaultCommunity``` will do this.  Note the script must be ran as admin to install automatically.  If it is problem then comment out the call to ```UpdateWindowsMachineStore``` and install the CA into your Windows personal Trust store yourself.  For Linux images running in Docker, the Dockerfile already has the build steps in place to do this.  

Also run the MakeCaWithIntermediateUdapForLocalhostCommunity unit test to generated many UDAP certificates used for testing.  

## Tiered OAuth

There is a Tiered OAuth path that will work locally with this current setup.  In the UdapEd tool type ```https://host.docker.internal:5057``` in the ```OpenID Connect IdP``` field.  Then use username/password of ```bob/bob``` or ```alice/alice```.
