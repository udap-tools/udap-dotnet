#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Udap.AppHost;

internal static class AppHostExtensions
{
    // Every *.dev.localhost name registered with WithDevHost, for containers that call those servers.
    private static readonly HashSet<string> DevHosts = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// pgAdmin as a plain persistent container rather than <c>WithPgAdmin()</c>.
    /// </summary>
    /// <remarks>
    /// <c>WithPgAdmin()</c> writes this AppHost's own server list into the container spec, so another AppHost
    /// sharing the same pgAdmin would recreate it on every start. This spec depends only on configuration:
    /// give two AppHosts the same container name, volume and servers file and they share one pgAdmin.
    /// The server list is imported once, when the volume is new.
    /// </remarks>
    public static IResourceBuilder<ContainerResource> AddSharedPgAdmin(
        this IDistributedApplicationBuilder builder,
        IConfigurationSection config,
        IResourceBuilder<PostgresServerResource> postgres)
    {
        // Normalized, because the path is part of the container spec two AppHosts must agree on.
        var serversFile = Path.GetFullPath(ExpandHome(config["ServersFile"] ?? "~/.udap-dotnet/pgadmin-servers.json"));
        if (!File.Exists(serversFile))
        {
            // The Postgres container answers to its container name on the network Aspire puts both containers on.
            var host = postgres.Resource.Annotations.OfType<ContainerNameAnnotation>().LastOrDefault()?.Name
                       ?? postgres.Resource.Name;
            Directory.CreateDirectory(Path.GetDirectoryName(serversFile)!);
            File.WriteAllText(serversFile, JsonSerializer.Serialize(new
            {
                Servers = new Dictionary<string, object>
                {
                    ["1"] = new
                    {
                        Name = host,
                        Group = "Servers",
                        Host = host,
                        Port = 5432,
                        Username = "postgres",
                        SSLMode = "prefer",
                        MaintenanceDB = "postgres"
                    }
                }
            }, new JsonSerializerOptions { WriteIndented = true }));
        }

        return builder.AddContainer("pgadmin", "dpage/pgadmin4", config["ImageTag"] ?? "9.15.0")
            .WithContainerName(config["ContainerName"] ?? "udap-pgadmin")
            .WithLifetime(ContainerLifetime.Persistent)
            .WithVolume(config["DataVolume"] ?? "udap-pgadmin-data", "/var/lib/pgadmin")
            .WithBindMount(serversFile, "/pgadmin4/shared-servers.json", isReadOnly: true)
            .WithEnvironment("PGADMIN_SERVER_JSON_FILE", "/pgadmin4/shared-servers.json")
            .WithEnvironment("PGADMIN_DEFAULT_EMAIL", "admin@domain.com")
            .WithEnvironment("PGADMIN_DEFAULT_PASSWORD", "admin")
            .WithEnvironment("PGADMIN_CONFIG_SERVER_MODE", "False")
            .WithEnvironment("PGADMIN_CONFIG_MASTER_PASSWORD_REQUIRED", "False")
            // Identity server cookies for every *.localhost app share one browser cookie jar and can overflow
            // gunicorn's 8190-byte header limit, which pgAdmin answers with 431.
            .WithEnvironment("GUNICORN_LIMIT_REQUEST_FIELD_SIZE", "32768")
            .WithHttpEndpoint(port: config.GetValue("Port", 5050), targetPort: 80, isProxied: false);
    }

    /// <summary>
    /// One run of migrations/UdapDb.Postgres: applies the schema to <paramref name="database"/>, seeds it,
    /// and exits. <paramref name="connectionName"/> is the ConnStrName the launch profile selects.
    /// </summary>
    public static IResourceBuilder<ProjectResource> AddUdapDbSeeder(
        this IDistributedApplicationBuilder builder,
        string name,
        string launchProfileName,
        IResourceBuilder<PostgresDatabaseResource> database,
        string connectionName)
    {
        return builder.AddProject<Projects.UdapDb_Postgres>(name, launchProfileName)
            .WithParentRelationship(database)
            .WithReference(database, connectionName)
            .WaitFor(database)
            // A web host that stops itself after seeding; any free port keeps the three runs from colliding.
            .WithEnvironment("ASPNETCORE_URLS", "http://127.0.0.1:0");
    }

    /// <summary>
    /// The resource answers to <paramref name="host"/> (a *.dev.localhost name) rather than localhost.
    /// </summary>
    /// <remarks>
    /// Points the dashboard links at that name, since the UDAP metadata, issuers and redirects all use it.
    /// Also checks at startup that the name resolves to loopback. Windows and browsers resolve *.localhost
    /// themselves, but some resolvers (a VPN, macOS) do not; then the app starts and every call to it fails
    /// with "No such host is known". The log says how to fix that.
    /// </remarks>
    public static IResourceBuilder<T> WithDevHost<T>(this IResourceBuilder<T> resource, string host)
        where T : IResourceWithEndpoints
    {
        DevHosts.Add(host);

        resource.ApplicationBuilder.Eventing.Subscribe<BeforeStartEvent>(async (@event, ct) =>
        {
            IPAddress[] addresses;
            try
            {
                addresses = await Dns.GetHostAddressesAsync(host, ct);
            }
            catch (SocketException)
            {
                addresses = [];
            }

            if (!addresses.Any(IPAddress.IsLoopback))
            {
                @event.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Udap.AppHost").LogError(
                    "{Host} does not resolve to this machine, so {Resource} cannot be reached by its name. " +
                    "Add this line to your hosts file: 127.0.0.1 {Host}",
                    host, resource.Resource.Name, host);
            }
        });

        return resource.WithUrls(context =>
        {
            foreach (var url in context.Urls)
            {
                if (Uri.TryCreate(url.Url, UriKind.Absolute, out var absolute) && absolute.IsLoopback)
                {
                    url.Url = new UriBuilder(absolute) { Host = host }.Uri.ToString();
                }
            }
        });
    }

    /// <summary>
    /// UdapEd, the UDAP test client, from its published container image, served at
    /// https://udaped.dev.localhost with the ASP.NET dev cert.
    /// </summary>
    /// <remarks>
    /// UdapEd's server side makes the UDAP calls, from inside the container. There every *.localhost name means the
    /// container itself, so each server name registered with <see cref="WithDevHost{T}"/> is mapped to the Docker
    /// host instead (--add-host name:host-gateway). The UDAP metadata, issuers and audiences then match exactly what
    /// the browser sees. The container trusts the dev cert, so those HTTPS calls validate.
    /// UdapEd/udap_urls.json replaces the image's base URL and IdP dropdown lists, which UdapEd reads from both
    /// paths below, so the local servers are listed first.
    /// </remarks>
    public static IResourceBuilder<ContainerResource> AddUdapEd(
        this IDistributedApplicationBuilder builder,
        IConfigurationSection config)
    {
        var urls = Path.Combine(builder.AppHostDirectory, "UdapEd", "udap_urls.json");

        return builder.AddContainer("udaped", config["Image"] ?? "ghcr.io/joeshook/udaped", config["ImageTag"] ?? "latest")
            .WithBindMount(urls, "/app/wwwroot/Packages/udap_urls.json", isReadOnly: true)
            .WithBindMount(urls, "/app/wwwroot/_content/UdapEd.Shared/Packages/udap_urls.json", isReadOnly: true)
            .WithImagePullPolicy(ImagePullPolicy.Always)
            .WithHttpsEndpoint(port: config.GetValue("Port", 7041), targetPort: 8181)
            .WithEnvironment("ASPNETCORE_HTTPS_PORTS", "8181")
            .WithHttpsDeveloperCertificate()
            .WithHttpsCertificateConfiguration(context =>
            {
                context.EnvironmentVariables["ASPNETCORE_Kestrel__Certificates__Default__Path"] = context.CertificatePath;
                context.EnvironmentVariables["ASPNETCORE_Kestrel__Certificates__Default__KeyPath"] = context.KeyPath;
                return Task.CompletedTask;
            })
            .WithDeveloperCertificateTrust(true)
            .WithContainerRuntimeArgs(context =>
            {
                foreach (var host in DevHosts)
                {
                    context.Args.Add("--add-host");
                    context.Args.Add($"{host}:host-gateway");
                }
            })
            .WithDevHost("udaped.dev.localhost");
    }

    /// <summary>
    /// Google credentials for the proxy from a gcloud config folder of its own, so the Google account it uses
    /// never touches the machine's usual gcloud login. Adds a "gcloud-login" resource, started from the dashboard,
    /// that runs <c>gcloud auth application-default login</c> against that folder, and points the proxy's
    /// GoogleCredentialsFile at the resulting credentials file whenever the proxy starts.
    /// </summary>
    public static IResourceBuilder<ProjectResource> WithSeparateGcloudLogin(
        this IResourceBuilder<ProjectResource> proxy,
        IConfigurationSection config)
    {
        var configDir = Path.GetFullPath(ExpandHome(config["GcloudConfigDir"] ?? "~/.udap-gcloud"));
        var credentialsFile = Path.Combine(configDir, "application_default_credentials.json");

        // gcloud is a .cmd script on Windows, so run it through cmd there.
        var login = OperatingSystem.IsWindows()
            ? proxy.ApplicationBuilder.AddExecutable("gcloud-login", "cmd", configDir,
                "/c", "gcloud", "auth", "application-default", "login")
            : proxy.ApplicationBuilder.AddExecutable("gcloud-login", "gcloud", configDir,
                "auth", "application-default", "login");

        Directory.CreateDirectory(configDir);

        login
            .WithEnvironment("CLOUDSDK_CONFIG", configDir)
            .WithExplicitStart()
            .WithParentRelationship(proxy);

        return proxy.WithEnvironment(context =>
        {
            // Checked at each proxy start, so a login made after the AppHost started is picked up.
            if (File.Exists(credentialsFile))
            {
                context.EnvironmentVariables["GoogleCredentialsFile"] = credentialsFile;
            }
        });
    }

    private static string ExpandHome(string path) =>
        path.StartsWith('~')
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), path[1..].TrimStart('/', '\\'))
            : path;
}
