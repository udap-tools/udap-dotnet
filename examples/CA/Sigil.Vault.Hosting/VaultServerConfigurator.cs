#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace Sigil.Vault.Hosting;

/// <summary>
/// For persistent-mode Vault: handles init, unseal, and well-known root token aliasing
/// after the container starts. Polls Vault HTTP directly (not via Aspire health) because
/// Vault starts sealed and the health check would never go green without our intervention.
/// </summary>
internal static class VaultServerConfigurator
{
    public static async Task EnsureVaultUsableAsync(
        string vaultAddress,
        string initStatePath,
        string knownRootToken,
        ILogger logger,
        CancellationToken ct)
    {
        using var client = new HttpClient { BaseAddress = new Uri(vaultAddress) };

        // 1. Wait for Vault to respond at all (container booting)
        await WaitForVaultReachableAsync(client, logger, ct);

        // 2. Initialize if needed
        var initStatus = await GetInitStatusAsync(client, ct);
        VaultInitState? state;
        if (!initStatus.Initialized)
        {
            logger.LogInformation("Initializing Vault at {Address}", vaultAddress);
            state = await InitializeAsync(client, ct);
            VaultInitStateStore.Save(initStatePath, state);
            logger.LogInformation("Vault initialized; init state saved to {Path}", initStatePath);
        }
        else
        {
            state = VaultInitStateStore.TryLoad(initStatePath);
            if (state == null)
            {
                logger.LogError(
                    "Vault at {Address} is already initialized but the init state file is missing at {Path}. " +
                    "Unseal keys are unrecoverable. Delete the Docker volume 'vault-*-data' and restart to start fresh.",
                    vaultAddress, initStatePath);
                return;
            }
        }

        // 3. Unseal if sealed
        await UnsealIfSealedAsync(client, state, logger, ct);

        // 4. Ensure the well-known root token alias exists (lets Sigil keep using "root-token")
        if (!string.Equals(state.RootToken, knownRootToken, StringComparison.Ordinal))
        {
            await EnsureRootTokenAliasAsync(client, state.RootToken, knownRootToken, logger, ct);
        }

        // 5. Mount the default KV v2 secrets engine at secret/ to match Vault dev mode behavior.
        // Server mode doesn't auto-mount this; dev mode does. Restoring parity so the Vault UI
        // looks the same in either mode.
        await EnsureKvSecretsMountedAsync(client, logger, ct);
    }

    private static async Task EnsureKvSecretsMountedAsync(HttpClient client, ILogger logger, CancellationToken ct)
    {
        // Check existing mounts
        using var listResponse = await client.GetAsync("/v1/sys/mounts", ct);
        if (listResponse.IsSuccessStatusCode)
        {
            var body = await listResponse.Content.ReadAsStringAsync(ct);
            if (body.Contains("\"secret/\"", StringComparison.Ordinal))
            {
                logger.LogDebug("KV secrets engine already mounted at secret/");
                return;
            }
        }

        var mountRequest = new
        {
            type = "kv",
            options = new Dictionary<string, string> { ["version"] = "2" },
            description = "key/value secret storage"
        };
        using var mountResponse = await client.PostAsJsonAsync("/v1/sys/mounts/secret", mountRequest, ct);
        if (mountResponse.IsSuccessStatusCode)
        {
            logger.LogInformation("Mounted KV v2 secrets engine at secret/");
        }
        else if ((int)mountResponse.StatusCode == 400)
        {
            // Already mounted — Vault returns 400 with "path already in use"
            logger.LogDebug("KV secrets engine already mounted at secret/");
        }
        else
        {
            var body = await mountResponse.Content.ReadAsStringAsync(ct);
            logger.LogWarning("Failed to mount KV secrets engine ({Status}): {Body}",
                mountResponse.StatusCode, body);
        }
    }

    private static async Task WaitForVaultReachableAsync(HttpClient client, ILogger logger, CancellationToken ct)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(60);
        while (DateTimeOffset.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var response = await client.GetAsync("/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200", ct);
                return;
            }
            catch (HttpRequestException)
            {
                await Task.Delay(500, ct);
            }
        }
        logger.LogWarning("Timed out waiting for Vault to be reachable at {Address}", client.BaseAddress);
    }

    private static async Task<InitStatusResponse> GetInitStatusAsync(HttpClient client, CancellationToken ct)
    {
        using var response = await client.GetAsync("/v1/sys/init", ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<InitStatusResponse>(ct)
            ?? throw new InvalidOperationException("Vault returned an empty init status response");
    }

    private static async Task<VaultInitState> InitializeAsync(HttpClient client, CancellationToken ct)
    {
        // Use 1 unseal key for dev simplicity (production would use 3-of-5 Shamir or auto-unseal)
        var initRequest = new { secret_shares = 1, secret_threshold = 1 };
        using var response = await client.PostAsJsonAsync("/v1/sys/init", initRequest, ct);
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException(
                $"Vault init failed ({(int)response.StatusCode}): {body}");
        }

        var init = await response.Content.ReadFromJsonAsync<InitResponse>(ct)
            ?? throw new InvalidOperationException("Vault init returned an empty response");

        return new VaultInitState(init.RootToken, init.Keys);
    }

    private static async Task UnsealIfSealedAsync(HttpClient client, VaultInitState state, ILogger logger, CancellationToken ct)
    {
        var sealStatus = await GetSealStatusAsync(client, ct);
        if (!sealStatus.Sealed) return;

        logger.LogInformation("Unsealing Vault");
        foreach (var key in state.UnsealKeys)
        {
            using var response = await client.PostAsJsonAsync("/v1/sys/unseal", new { key }, ct);
            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(ct);
                throw new InvalidOperationException(
                    $"Vault unseal failed ({(int)response.StatusCode}): {body}");
            }
            sealStatus = await response.Content.ReadFromJsonAsync<SealStatusResponse>(ct)
                ?? throw new InvalidOperationException("Vault unseal returned an empty response");
            if (!sealStatus.Sealed) break;
        }
        logger.LogInformation("Vault unsealed");
    }

    private static async Task<SealStatusResponse> GetSealStatusAsync(HttpClient client, CancellationToken ct)
    {
        using var response = await client.GetAsync("/v1/sys/seal-status", ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<SealStatusResponse>(ct)
            ?? throw new InvalidOperationException("Vault returned an empty seal-status response");
    }

    private static async Task EnsureRootTokenAliasAsync(
        HttpClient client, string actualRootToken, string knownAlias,
        ILogger logger, CancellationToken ct)
    {
        // First check whether the alias already exists by trying to look it up
        client.DefaultRequestHeaders.Remove("X-Vault-Token");
        client.DefaultRequestHeaders.Add("X-Vault-Token", actualRootToken);

        using (var lookupResponse = await client.PostAsJsonAsync(
            "/v1/auth/token/lookup",
            new { token = knownAlias },
            ct))
        {
            if (lookupResponse.IsSuccessStatusCode)
            {
                logger.LogDebug("Vault root token alias '{Alias}' already exists", knownAlias);
                return;
            }
        }

        // Create the alias
        var createRequest = new
        {
            id = knownAlias,
            policies = new[] { "root" },
            no_parent = true,
            ttl = "0",
            display_name = "sigil-known-root"
        };
        using var createResponse = await client.PostAsJsonAsync("/v1/auth/token/create", createRequest, ct);
        if (!createResponse.IsSuccessStatusCode)
        {
            var body = await createResponse.Content.ReadAsStringAsync(ct);
            logger.LogWarning(
                "Failed to create root token alias '{Alias}' ({Status}): {Body}. " +
                "Sigil will need to use the actual root token ({ActualToken})",
                knownAlias, (int)createResponse.StatusCode, body, actualRootToken);
            return;
        }
        logger.LogInformation("Created Vault root token alias '{Alias}'", knownAlias);
    }

    private sealed record InitStatusResponse(
        [property: JsonPropertyName("initialized")] bool Initialized);

    private sealed record InitResponse(
        [property: JsonPropertyName("keys")] List<string> Keys,
        [property: JsonPropertyName("keys_base64")] List<string> KeysBase64,
        [property: JsonPropertyName("root_token")] string RootToken);

    private sealed record SealStatusResponse(
        [property: JsonPropertyName("sealed")] bool Sealed,
        [property: JsonPropertyName("t")] int Threshold,
        [property: JsonPropertyName("n")] int Shares,
        [property: JsonPropertyName("progress")] int Progress);
}
