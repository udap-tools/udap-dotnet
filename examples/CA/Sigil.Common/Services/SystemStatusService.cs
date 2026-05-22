#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sigil.Common.Data;
using Sigil.Common.ViewModels;

namespace Sigil.Common.Services;

public class SystemStatusOptions
{
    public string DefaultProvider { get; set; } = "local";
    public List<string> AvailableProviders { get; set; } = new() { "local" };
    public string? VaultAddress { get; set; }
    public string? VaultToken { get; set; }
    public string? GcpProjectId { get; set; }
}

public class SystemStatusService
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(30);

    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptions<SystemStatusOptions> _options;
    private readonly ILogger<SystemStatusService> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private SystemStatusViewModel? _cached;
    private DateTimeOffset _cachedAt;

    public SystemStatusService(
        IDbContextFactory<SigilDbContext> dbFactory,
        IHttpClientFactory httpClientFactory,
        IOptions<SystemStatusOptions> options,
        ILogger<SystemStatusService> logger)
    {
        _dbFactory = dbFactory;
        _httpClientFactory = httpClientFactory;
        _options = options;
        _logger = logger;
    }

    public async Task<SystemStatusViewModel> GetStatusAsync(bool forceRefresh = false, CancellationToken ct = default)
    {
        if (!forceRefresh && _cached != null && DateTimeOffset.UtcNow - _cachedAt < CacheTtl)
            return _cached;

        await _gate.WaitAsync(ct);
        try
        {
            if (!forceRefresh && _cached != null && DateTimeOffset.UtcNow - _cachedAt < CacheTtl)
                return _cached;

            var opts = _options.Value;
            var dbResult = await CheckDatabaseAsync(ct);
            var vaultStatus = await CheckVaultAsync(opts, ct);
            var gcpStatus = CheckGcp(opts);

            _cached = new SystemStatusViewModel(
                DatabaseConnected: dbResult.connected,
                DatabaseError: dbResult.error,
                DefaultProvider: opts.DefaultProvider,
                AvailableProviders: opts.AvailableProviders,
                VaultStatus: vaultStatus,
                VaultAddress: opts.VaultAddress,
                GcpKmsStatus: gcpStatus,
                GcpProjectId: opts.GcpProjectId,
                CheckedAt: DateTimeOffset.UtcNow);
            _cachedAt = DateTimeOffset.UtcNow;
            return _cached;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<(bool connected, string? error)> CheckDatabaseAsync(CancellationToken ct)
    {
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync(ct);
            var ok = await db.Database.CanConnectAsync(ct);
            return (ok, ok ? null : "Cannot connect");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Database health check failed");
            return (false, ex.Message);
        }
    }

    private async Task<ComponentStatus> CheckVaultAsync(SystemStatusOptions opts, CancellationToken ct)
    {
        if (!opts.AvailableProviders.Contains("vault-transit") ||
            string.IsNullOrWhiteSpace(opts.VaultAddress) ||
            string.IsNullOrWhiteSpace(opts.VaultToken))
        {
            return ComponentStatus.NotConfigured;
        }

        try
        {
            using var client = _httpClientFactory.CreateClient("VaultTransit");
            client.BaseAddress = new Uri(opts.VaultAddress);
            client.Timeout = TimeSpan.FromSeconds(2);
            using var response = await client.GetAsync("/v1/sys/health", ct);
            return response.IsSuccessStatusCode || (int)response.StatusCode is 429 or 472 or 473
                ? ComponentStatus.Reachable
                : ComponentStatus.Unreachable;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Vault health check failed");
            return ComponentStatus.Unreachable;
        }
    }

    private static ComponentStatus CheckGcp(SystemStatusOptions opts)
    {
        if (!opts.AvailableProviders.Contains("gcp-kms") || string.IsNullOrWhiteSpace(opts.GcpProjectId))
            return ComponentStatus.NotConfigured;

        return ComponentStatus.Reachable;
    }
}
