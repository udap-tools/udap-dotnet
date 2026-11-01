# Running the examples

The example servers are meant to run together. [`Udap.AppHost`](./Udap.AppHost/) is a .NET Aspire AppHost that starts them all, plus Postgres and pgAdmin, and gives you a dashboard of what is running where.

## Before the first run

- **.NET 10 SDK** and **Docker** (Docker Desktop or Podman) running.
- **A trusted ASP.NET dev certificate.** Every server serves HTTPS with it, and its SAN includes `*.dev.localhost`:

  ```bash
  dotnet dev-certs https --trust
  ```

- **The test PKI.** The UDAP certificates the servers sign metadata with, and trust, come from `_tests/Udap.PKI.Generator` (see [Certificates](#certificates)).

## Start

```bash
dotnet run --project examples/Udap.AppHost
```

The console prints the dashboard login link. The AppHost creates the databases, runs `migrations/UdapDb.Postgres` once per database to apply the schema and seed data, then starts the servers.

| Server | URL | Starts |
|:---|:---|:---|
| Udap.Auth.Server | https://udap-auth-server.dev.localhost:5002 | automatically |
| Udap.Identity.Provider | https://udap-idp1.dev.localhost:5055 | automatically |
| Udap.Identity.Provider.2 | https://udap-idp2.dev.localhost:5057 | automatically |
| FhirLabsApi | https://udap-fhirlabs-api.dev.localhost:7016/fhir/r4 | automatically |
| Udap.Certificates.Server (CRLs and AIA) | http://udap-cert-server.dev.localhost:5033 | automatically |
| Udap.Proxy.Server | https://udap-proxy.dev.localhost:7074 | from the dashboard |
| Tefca.Proxy.Server | https://udap-tefca-proxy.dev.localhost:7075 | from the dashboard |
| mTLS.Proxy.Server | https://udap-mtls-proxy.dev.localhost:7057 | from the dashboard |
| Udap.Auth.Server.Admin | http://udap-auth-admin.dev.localhost:5253 | from the dashboard |
| UdapEd (container) | https://udaped.dev.localhost:7041 | automatically |
| pgAdmin | http://localhost:5050 | automatically |

There is no hosts file to edit. Browsers, curl and .NET resolve any `*.localhost` name to the loopback address themselves. If a name ever stops resolving (some VPN clients, or macOS resolvers), the AppHost logs which one and the hosts-file line that fixes it.

Under the AppHost there are no connection strings to set up: it hands each server and seeder its database's connection string.

[UdapEd](https://github.com/JoeShook/UdapEd) runs from its published image, `ghcr.io/joeshook/udaped`. It serves the dev certificate, trusts it, and reaches the servers by the same names as your browser, so you can point it straight at `https://udap-fhirlabs-api.dev.localhost:7016/fhir/r4`. To skip it, or to pin an image tag, set `UdapEd:Enabled` or `UdapEd:ImageTag` in the AppHost's user secrets.

### Running a server on its own

You can run any server with `dotnet run --project examples/<Server>`. Its default launch profile uses the same name and port as under the AppHost. A server that uses a database then needs a Postgres you provide, with its database seeded. Put the connection strings in each project's `secrets.json`, which overrides `appsettings*.json` in Development. Open it with **Manage User Secrets** in Visual Studio, or set values with `dotnet user-secrets`.

**The seeder** (`migrations/UdapDb.Postgres`) needs all three. Each `Local_*_Migrate` launch profile picks one by name:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Port=5432;Database=Udap.Auth.db;Username=<user>;Password=<password>",
    "db_identity_provider": "Host=localhost;Port=5432;Database=Udap.Identity.Provider.db;Username=<user>;Password=<password>",
    "db_identity_provider2": "Host=localhost;Port=5432;Database=Udap.Identity.Provider2.db;Username=<user>;Password=<password>"
  }
}
```

Run the profile for each database you need. The user must be allowed to create the database:

```bash
dotnet run --project migrations/UdapDb.Postgres --launch-profile Local_Auth_Migrate
dotnet run --project migrations/UdapDb.Postgres --launch-profile Local_Idp1_Migrate
dotnet run --project migrations/UdapDb.Postgres --launch-profile Local_Idp2_Migrate
```

**Each server** reads `DefaultConnection`:

| Project | Database |
|:---|:---|
| Udap.Auth.Server | Udap.Auth.db |
| Udap.Auth.Server.Admin | Udap.Auth.db |
| Udap.Identity.Provider | Udap.Identity.Provider.db |
| Udap.Identity.Provider.2 | Udap.Identity.Provider2.db |

```bash
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Host=localhost;Port=5432;Database=Udap.Auth.db;Username=<user>;Password=<password>" --project examples/Udap.Auth.Server
```

Without secrets, the servers fall back to `udap_user` / `udap_password1` on `localhost:5432` (their `appsettings.Development.json`). The seeder falls back to `admin` / `admin1234` (its `appsettings.json`).

FhirLabsApi, the certificate server and the proxies use no database.

### Udap.Proxy.Server and Google Cloud

In Development, Udap.Proxy.Server forwards FHIR calls to a Google Cloud Healthcare FHIR store and calls it with a Google access token.

Under the AppHost, the proxy has a Google login of its own, kept in a separate gcloud config folder (`~/.udap-gcloud`, set by `UdapProxy:GcloudConfigDir`). Your usual gcloud login, and every other tool on the machine, never sees it. To sign in, start **gcloud-login** under udap-proxy on the dashboard and sign in with the Google account that can read the FHIR store. Then start or restart udap-proxy. The AppHost hands the proxy that login's credentials file at each start. Sign in again the same way to switch accounts.

Run on its own, the proxy uses Google application default credentials, the account from `gcloud auth application-default login`, shared by every tool on the machine. To give it other credentials, point `GoogleCredentialsFile` in its user secrets at a credential file that can read the store, either a service account key or a user's `application_default_credentials.json`:

```bash
dotnet user-secrets set GoogleCredentialsFile "<path to the credential file>" --project examples/Udap.Proxy.Server
```

Keep the credential file outside the repo.

### Sharing an existing Postgres and pgAdmin

Postgres and pgAdmin are persistent containers, by default `udap-postgres` and `udap-pgadmin`. Their names, volumes and image tags come from [`appsettings.json`](./Udap.AppHost/appsettings.json). To use a Postgres and pgAdmin you already run for other projects, override them in the AppHost's user secrets. Aspire reuses a container whose name and spec match, rather than creating a new one:

```bash
cd examples/Udap.AppHost
dotnet user-secrets set Parameters:postgres-password "<that server's postgres password>"
dotnet user-secrets set Postgres:ContainerName "<postgres container>"
dotnet user-secrets set Postgres:DataVolume "<its data volume>"
dotnet user-secrets set PgAdmin:ContainerName "<pgadmin container>"
dotnet user-secrets set PgAdmin:DataVolume "<its data volume>"
dotnet user-secrets set PgAdmin:ServersFile "<the servers.json file it mounts>"
```

The image tags, volumes and pgAdmin servers file must match how the other project declares the containers, or Aspire recreates them with this spec. The data stays on the volumes, but the other project's next start recreates them back. Set `PgAdmin:Enabled` to `false` to skip pgAdmin.

## Certificates

**HTTPS** uses the ASP.NET dev certificate (above). Nothing to generate.

**UDAP certificates** come from the test PKI generator. Their SAN URIs name the servers' base URLs (for example `https://udap-fhirlabs-api.dev.localhost:7016/fhir/r4`). Their CRL distribution points and AIA URLs point at `http://udap-cert-server.dev.localhost:5033`. After a fresh clone, generate everything once:

```bash
dotnet test _tests/Udap.PKI.Generator
```

To regenerate only the local communities, after changing a host name for example, run these tests and nothing else:

```bash
dotnet test _tests/Udap.PKI.Generator --filter "FullyQualifiedName~MakeCaWithIntermediateUdapForLocalhostCommunity|FullyQualifiedName~MakeNegativeTestCerts|FullyQualifiedName~MakeMultiDomainCertsForSureFhirLabs|FullyQualifiedName~BuildTefcaTestPkiDesk"
```

Then, as a separate run, reissue Udap.Proxy.Server's local cert from the new community 1 intermediate:

```bash
dotnet test _tests/Udap.PKI.Generator --filter "FullyQualifiedName~MakeUdapProxyLocalhostCert"
```

The SureFhirLabs CA is never replaced once it exists, because deployed servers trust it. Regenerated anchors change what the auth server and identity providers trust, so re-seed their databases afterwards: drop the `Udap.*` databases and start the AppHost again.

## Tiered OAuth

Tiered OAuth works locally. In [UdapEd](https://github.com/JoeShook/UdapEd), enter `https://udap-idp2.dev.localhost:5057` in the **OpenID Connect IdP** field, then sign in as `bob` / `bob` or `alicenewman@example.com` / `alice`. The sign-in page lists the test accounts.
