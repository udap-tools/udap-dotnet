#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sigil.Common.Services.Signing;

namespace Sigil.Vault;

/// <summary>
/// Signing provider that delegates to HashiCorp Vault's Transit secrets engine.
/// Private keys never leave Vault — only the signature is returned.
/// </summary>
public sealed class VaultTransitSigningProvider : ISigningProvider
{
    public string ProviderName => "vault-transit";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly VaultTransitOptions _options;
    private readonly ILogger<VaultTransitSigningProvider> _logger;

    public VaultTransitSigningProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<VaultTransitOptions> options,
        ILogger<VaultTransitSigningProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<SigningKeyReference> GenerateKeyAsync(
        string keyAlgorithm, int keySize, string? ecdsaCurve = null,
        CancellationToken ct = default)
    {
        var vaultKeyType = MapToVaultKeyType(keyAlgorithm, keySize, ecdsaCurve);
        var keyName = $"sigil-{Guid.NewGuid():N}";

        using var client = CreateClient();

        var response = await client.PostAsync(
            $"/v1/{_options.MountPath}/keys/{keyName}",
            JsonContent(new { type = vaultKeyType }),
            ct);

        response.EnsureSuccessStatusCode();

        _logger.LogInformation("Created Vault Transit key '{Name}' (type: {Type})", keyName, vaultKeyType);

        return new SigningKeyReference("vault-transit", keyName, keyAlgorithm, keySize);
    }

    public async Task<AsymmetricAlgorithm> GetPublicKeyAsync(
        SigningKeyReference keyRef, CancellationToken ct = default)
    {
        using var client = CreateClient();

        var response = await client.GetAsync(
            $"/v1/{_options.MountPath}/keys/{keyRef.KeyIdentifier}",
            ct);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync(ct);
        var doc = JsonDocument.Parse(json);

        // Navigate: data.keys."1".public_key
        var keys = doc.RootElement.GetProperty("data").GetProperty("keys");
        var latestKey = keys.GetProperty("1");
        var publicKeyPem = latestKey.GetProperty("public_key").GetString()
            ?? throw new InvalidOperationException("No public key in Vault response");

        if (keyRef.KeyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(publicKeyPem);
            return ecdsa;
        }
        else
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);
            return rsa;
        }
    }

    public async Task<byte[]> SignDataAsync(
        byte[] data, HashAlgorithmName hashAlgorithm,
        SigningKeyReference keyRef, CancellationToken ct = default)
    {
        // Vault Transit expects pre-hashed data with prehashed=true,
        // or raw data as base64 input
        var input = Convert.ToBase64String(data);
        var hashName = hashAlgorithm.Name?.ToLowerInvariant() ?? "sha2-256";

        // Map .NET hash names to Vault hash names
        var vaultHash = hashName switch
        {
            "sha256" => "sha2-256",
            "sha384" => "sha2-384",
            "sha512" => "sha2-512",
            _ => "sha2-256"
        };

        var signatureAlgorithm = keyRef.KeyAlgorithm.Equals("RSA", StringComparison.OrdinalIgnoreCase)
            ? "pkcs1v15"
            : null; // ECDSA uses default

        var requestBody = new Dictionary<string, object>
        {
            ["input"] = input,
            ["hash_algorithm"] = vaultHash,
        };

        if (signatureAlgorithm != null)
            requestBody["signature_algorithm"] = signatureAlgorithm;

        using var client = CreateClient();

        var response = await client.PostAsync(
            $"/v1/{_options.MountPath}/sign/{keyRef.KeyIdentifier}",
            JsonContent(requestBody),
            ct);

        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync(ct);
            _logger.LogError(
                "Vault Transit sign failed for key '{KeyName}': {Status} — body: {Body}. Request: hash={Hash}, sigAlg={SigAlg}, keyAlg={KeyAlg}, dataLen={DataLen}",
                keyRef.KeyIdentifier, (int)response.StatusCode, errorBody,
                vaultHash, signatureAlgorithm ?? "(default)", keyRef.KeyAlgorithm, data.Length);
            throw new InvalidOperationException(
                $"Vault Transit sign failed ({(int)response.StatusCode}) for key '{keyRef.KeyIdentifier}': {errorBody}");
        }

        var json = await response.Content.ReadAsStringAsync(ct);
        var doc = JsonDocument.Parse(json);

        // Response: data.signature = "vault:v1:<base64>"
        var signature = doc.RootElement.GetProperty("data").GetProperty("signature").GetString()
            ?? throw new InvalidOperationException("No signature in Vault response");

        // Strip "vault:v1:" prefix
        var parts = signature.Split(':');
        if (parts.Length != 3 || parts[0] != "vault")
            throw new InvalidOperationException($"Unexpected Vault signature format: {signature[..Math.Min(30, signature.Length)]}...");

        var signatureBytes = Convert.FromBase64String(parts[2]);

        // For ECDSA: Vault returns P1363 format, BouncyCastle expects DER.
        // Convert if needed.
        if (keyRef.KeyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            signatureBytes = ConvertP1363ToDer(signatureBytes);
        }

        return signatureBytes;
    }

    /// <summary>
    /// Checks whether a Transit key exists in Vault.
    /// Returns true if the key exists, false if Vault returns 404 or the request fails.
    /// </summary>
    public async Task<bool> KeyExistsAsync(string keyName, CancellationToken ct = default)
    {
        try
        {
            using var client = CreateClient();
            using var response = await client.GetAsync($"/v1/{_options.MountPath}/keys/{keyName}", ct);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Vault Transit key existence check failed for '{Name}'", keyName);
            return false;
        }
    }

    /// <summary>
    /// Deletes a Transit key from Vault. Vault keys are deletion-protected by default,
    /// so this first enables deletion via config update, then deletes.
    /// </summary>
    public async Task DeleteKeyAsync(string keyName, CancellationToken ct = default)
    {
        using var client = CreateClient();

        // Step 1: Enable deletion (Vault protects keys by default)
        var configResponse = await client.PostAsync(
            $"/v1/{_options.MountPath}/keys/{keyName}/config",
            JsonContent(new { deletion_allowed = true }),
            ct);

        if (!configResponse.IsSuccessStatusCode)
        {
            var body = await configResponse.Content.ReadAsStringAsync(ct);
            _logger.LogWarning("Failed to enable deletion for Transit key '{Name}': {Status} {Body}",
                keyName, configResponse.StatusCode, body);
            return;
        }

        // Step 2: Delete the key
        var deleteResponse = await client.DeleteAsync(
            $"/v1/{_options.MountPath}/keys/{keyName}",
            ct);

        if (deleteResponse.IsSuccessStatusCode)
        {
            _logger.LogInformation("Deleted Vault Transit key '{Name}'", keyName);
        }
        else
        {
            var body = await deleteResponse.Content.ReadAsStringAsync(ct);
            _logger.LogWarning("Failed to delete Transit key '{Name}': {Status} {Body}",
                keyName, deleteResponse.StatusCode, body);
        }
    }

    /// <summary>
    /// Converts IEEE P1363 format (r || s) to DER-encoded ECDSA signature.
    /// </summary>
    internal static byte[] ConvertP1363ToDer(byte[] p1363Signature)
    {
        int halfLen = p1363Signature.Length / 2;
        ReadOnlySpan<byte> r = p1363Signature.AsSpan(0, halfLen);
        ReadOnlySpan<byte> s = p1363Signature.AsSpan(halfLen, halfLen);

        // Trim leading zeros but keep one if the high bit is set
        r = TrimLeadingZeros(r);
        s = TrimLeadingZeros(s);

        // Add leading zero byte if high bit is set (DER integer encoding)
        bool rNeedsPad = (r[0] & 0x80) != 0;
        bool sNeedsPad = (s[0] & 0x80) != 0;

        int rLen = r.Length + (rNeedsPad ? 1 : 0);
        int sLen = s.Length + (sNeedsPad ? 1 : 0);
        int seqLen = 2 + rLen + 2 + sLen;

        var der = new byte[2 + seqLen];
        int offset = 0;

        // SEQUENCE
        der[offset++] = 0x30;
        der[offset++] = (byte)seqLen;

        // INTEGER r
        der[offset++] = 0x02;
        der[offset++] = (byte)rLen;
        if (rNeedsPad) der[offset++] = 0x00;
        r.CopyTo(der.AsSpan(offset));
        offset += r.Length;

        // INTEGER s
        der[offset++] = 0x02;
        der[offset++] = (byte)sLen;
        if (sNeedsPad) der[offset++] = 0x00;
        s.CopyTo(der.AsSpan(offset));

        return der;
    }

    private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
    {
        int i = 0;
        while (i < value.Length - 1 && value[i] == 0) i++;
        return value[i..];
    }

    private static string MapToVaultKeyType(string keyAlgorithm, int keySize, string? ecdsaCurve)
    {
        if (keyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            return ecdsaCurve?.ToLowerInvariant() switch
            {
                "nistp256" => "ecdsa-p256",
                "nistp384" => "ecdsa-p384",
                "nistp521" => "ecdsa-p521",
                _ => "ecdsa-p384"
            };
        }

        return keySize switch
        {
            2048 => "rsa-2048",
            3072 => "rsa-3072",
            4096 => "rsa-4096",
            _ => $"rsa-{keySize}"
        };
    }

    private HttpClient CreateClient()
    {
        var client = _httpClientFactory.CreateClient("VaultTransit");
        client.BaseAddress = new Uri(_options.Address);
        client.DefaultRequestHeaders.Remove("X-Vault-Token");
        client.DefaultRequestHeaders.Add("X-Vault-Token", _options.Token);
        return client;
    }

    private static StringContent JsonContent(object value)
    {
        return new StringContent(
            JsonSerializer.Serialize(value),
            Encoding.UTF8,
            "application/json");
    }
}
