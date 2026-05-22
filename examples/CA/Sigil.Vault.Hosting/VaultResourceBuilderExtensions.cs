#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Aspire.Hosting.Eventing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;

namespace Sigil.Vault.Hosting;

public static class VaultResourceBuilderExtensions
{
    private const string PersistentConfigJson = """
        {
          "storage": { "file": { "path": "/vault/file" } },
          "listener": { "tcp": { "address": "0.0.0.0:8200", "tls_disable": "true" } },
          "ui": true,
          "disable_mlock": true,
          "api_addr": "http://0.0.0.0:8200"
        }
        """;

    /// <summary>
    /// Adds a HashiCorp Vault container.
    /// </summary>
    /// <param name="builder">The Aspire app host builder.</param>
    /// <param name="name">Resource name.</param>
    /// <param name="rootToken">
    /// Well-known root token Sigil uses to authenticate.
    /// In dev mode this is Vault's actual root token.
    /// In persistent mode this is created as an alias of Vault's randomly-generated root token after init.
    /// </param>
    /// <param name="port">Optional host port override; defaults to 8200.</param>
    /// <param name="persistent">
    /// false (default) = dev mode: in-memory storage, all keys lost on every restart.
    /// true = server mode: file-backed storage in a Docker volume, auto-init + auto-unseal,
    /// signing keys survive container restarts. Init state (root token + unseal keys) stored
    /// on the host filesystem at %LOCALAPPDATA%/Sigil/vault-{name}-init.json.
    /// </param>
    public static IResourceBuilder<VaultResource> AddVaultDev(
        this IDistributedApplicationBuilder builder,
        string name,
        string rootToken = "root-token",
        int? port = null,
        bool persistent = false)
    {
        var resource = new VaultResource(name)
        {
            RootToken = rootToken,
            IsPersistent = persistent,
            HostInitStatePath = persistent ? VaultInitStateStore.GetDefaultPath(name) : null
        };

        var health = builder.Services.AddHealthChecks();

        var resourceBuilder = builder.AddResource(resource)
            .WithContainerName($"vault-{name}")
            .WithAnnotation(new ContainerImageAnnotation
            {
                Image = VaultContainerImageTags.Image,
                Tag = VaultContainerImageTags.Tag,
                Registry = VaultContainerImageTags.Registry
            })
            .WithContainerRuntimeArgs("--cap-add", "IPC_LOCK")
            .WithEndpoint(
                port ?? VaultResource.DefaultPort,
                VaultResource.DefaultPort,
                name: VaultResource.HttpEndpointName,
                scheme: "http");

        if (persistent)
        {
            // Server mode: file-backed storage, auto-init + auto-unseal handled by VaultServerConfigurator.
            // VAULT_LOCAL_CONFIG is read by the Vault entrypoint and written to /vault/config/local.json.
            resourceBuilder
                .WithEnvironment("VAULT_LOCAL_CONFIG", PersistentConfigJson)
                .WithArgs("server")
                .WithVolume($"vault-{name}-data", "/vault/file");
        }
        else
        {
            resourceBuilder
                .WithEnvironment("VAULT_DEV_ROOT_TOKEN_ID", rootToken)
                .WithEnvironment("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200");
        }

        return resourceBuilder.WithHealthCheck(health, name, persistent);
    }

    /// <summary>
    /// Configures the Transit secrets engine with the specified signing keys.
    /// In dev mode, keys are recreated on every Vault start (Vault dev mode is in-memory).
    /// In persistent mode, also runs init + unseal + well-known root token alias before
    /// configuring Transit so the engine + keys are always available after a restart.
    /// </summary>
    public static IResourceBuilder<VaultResource> WithTransitEngine(
        this IResourceBuilder<VaultResource> builder,
        params TransitKeySpec[] keys)
    {
        builder.Resource.TransitKeys.AddRange(keys);

        builder.ApplicationBuilder.Eventing.Subscribe<AfterResourcesCreatedEvent>(
            (@event, ct) =>
            {
                foreach (var vault in @event.Model.Resources.OfType<VaultResource>())
                {
                    if (vault.TransitKeys.Count == 0) continue;
                    _ = WatchAndConfigureAsync(vault, @event.Services, ct);
                }
                return Task.CompletedTask;
            });

        return builder;
    }

    private static async Task WatchAndConfigureAsync(
        VaultResource vault,
        IServiceProvider services,
        CancellationToken ct)
    {
        var logger = services.GetRequiredService<ILogger<VaultResource>>();
        var notificationService = services.GetRequiredService<ResourceNotificationService>();

        bool wasHealthy = false;

        try
        {
            await foreach (var update in notificationService.WatchAsync(ct))
            {
                if (update.Resource is not VaultResource vr || vr.Name != vault.Name)
                    continue;

                var healthy = update.Snapshot.HealthStatus == HealthStatus.Healthy;

                if (healthy && !wasHealthy)
                {
                    wasHealthy = true;
                    try
                    {
                        var endpoint = vault.GetEndpoint(VaultResource.HttpEndpointName);
                        var vaultAddress = $"http://localhost:{endpoint.Port}";

                        if (vault.IsPersistent && vault.HostInitStatePath != null)
                        {
                            logger.LogInformation(
                                "Vault '{Name}' is reachable — ensuring init + unseal (persistent mode)",
                                vault.Name);
                            await VaultServerConfigurator.EnsureVaultUsableAsync(
                                vaultAddress, vault.HostInitStatePath, vault.RootToken, logger, ct);
                        }

                        logger.LogInformation(
                            "Vault '{Name}' is healthy — (re)configuring Transit engine",
                            vault.Name);
                        await VaultTransitConfigurator.ConfigureTransitAsync(
                            vaultAddress, vault.RootToken, vault.TransitKeys, logger, ct);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex,
                            "Failed to configure Vault for resource '{Name}'",
                            vault.Name);
                    }
                }
                else if (!healthy)
                {
                    wasHealthy = false;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Shutting down — ignore
        }
    }

    private static IResourceBuilder<VaultResource> WithHealthCheck(
        this IResourceBuilder<VaultResource> builder,
        IHealthChecksBuilder health,
        string name,
        bool persistent)
    {
        // In persistent mode, Vault starts uninitialized (501) then sealed (503). We pass
        // uninitcode=200&sealedcode=200 so the health endpoint reports 200 in those states,
        // letting Aspire mark the resource healthy while VaultServerConfigurator handles
        // init + unseal in the background.
        var healthQuery = persistent
            ? "?uninitcode=200&sealedcode=200&standbyok=true"
            : string.Empty;

        health.AddUrlGroup(
            _ => new Uri($"http://localhost:{VaultResource.DefaultPort}/v1/sys/health{healthQuery}"),
            $"{name}-vault-health",
            HealthStatus.Unhealthy);

        return builder.WithHealthCheck($"{name}-vault-health");
    }
}
