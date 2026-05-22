#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Models;
using Udap.Model;
using Udap.Util.Extensions;

namespace Udap.Client;

/// <summary>
/// Validator orchestrates JWT validation followed by x509 chain validation
/// </summary>
public class UdapClientDiscoveryValidator : IUdapClientEvents
{
    private readonly TrustChainValidator _trustChainValidator;
    private readonly ITrustAnchorStore? _trustAnchorStore;
    private readonly ILogger<UdapClientDiscoveryValidator> _logger;
    private X509Certificate2? _publicCertificate;

    public UdapClientDiscoveryValidator(
        TrustChainValidator trustChainValidator,
        ILogger<UdapClientDiscoveryValidator> logger,
        ITrustAnchorStore? trustAnchorStore = null)
    {
        _trustChainValidator = trustChainValidator;
        _trustAnchorStore = trustAnchorStore;
        _logger = logger;
    }

    /// <inheritdoc/>
    public event Action<X509Certificate2>? Untrusted
    {
        add => _trustChainValidator.Untrusted += value;
        remove => _trustChainValidator.Untrusted -= value;
    }

    /// <inheritdoc/>
    public event Action<ChainElementInfo>? Problem
    {
        add => _trustChainValidator.Problem += value;
        remove => _trustChainValidator.Problem -= value;
    }

    /// <inheritdoc/>
    public event Action<X509Certificate2, Exception>? Error
    {
        add => _trustChainValidator.Error += value;
        remove => _trustChainValidator.Error -= value;
    }

    /// <inheritdoc/>
    public event Action<string>? TokenError;

    public UdapMetadata? UdapServerMetadata { get; set; }

    /// <summary>
    /// Validates the signed JWT in the UDAP server metadata, verifying the signature, issuer, lifetime, and algorithm constraints.
    /// </summary>
    /// <param name="udapServerMetaData">The deserialized UDAP metadata containing the signed metadata JWT.</param>
    /// <param name="baseUrl">The FHIR server base URL that must match the JWT issuer claim.</param>
    /// <returns><c>true</c> if the JWT is valid; otherwise <c>false</c>.</returns>
    public virtual async Task<bool> ValidateJwtToken(UdapMetadata udapServerMetaData, string baseUrl)
    {
        var tokenHandler = new JsonWebTokenHandler();

        if (udapServerMetaData.SignedMetadata == null)
        {
            NotifyTokenError($"SignedMetadata is missing at {baseUrl}");
        }

        var jwt = tokenHandler.ReadJsonWebToken(udapServerMetaData.SignedMetadata);
        _publicCertificate = jwt?.GetPublicCertificate();

        if (_publicCertificate == null)
        {
            NotifyTokenError("Software statement is missing the x5c header.");
            return false;
        }

        var subjectAltNames = _publicCertificate
            .GetSubjectAltNames(n =>
                n.TagNo == (int)X509Extensions.GeneralNameType.URI) //URI only, by udap.org specification
            .Select(n => new Uri(n.Item2).OriginalString)
            .ToList();

        DenormalizeSubjectAltNames(subjectAltNames);

        var validatedToken = await ValidateToken(udapServerMetaData, tokenHandler, subjectAltNames.ToArray(), jwt);

        if (!validatedToken.IsValid)
        {
            NotifyTokenError(validatedToken.Exception.Message);
            return false;
        }

        if (!baseUrl.TrimEnd('/').Equals(jwt?.Issuer.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
        {
            NotifyTokenError($"JWT iss does not match baseUrl. iss: {jwt?.Issuer.TrimEnd('/')}  baseUrl: {baseUrl.TrimEnd('/')}");
            return false;
        }

        if (udapServerMetaData.RegistrationEndpointJwtSigningAlgValuesSupported != null && !udapServerMetaData.RegistrationEndpointJwtSigningAlgValuesSupported
                .Contains(jwt.GetHeaderValue<string>(JwtHeaderParameterNames.Alg)))
        {
            if (udapServerMetaData.TokenEndpointAuthSigningAlgValuesSupported != null)
            {
                NotifyTokenError(
                    $"The x5c header does not match one of the algorithms listed in {UdapConstants.Discovery.TokenEndpointAuthSigningAlgValuesSupported}:" +
                    $"{string.Join(", ", udapServerMetaData.TokenEndpointAuthSigningAlgValuesSupported)} ");
            }

            return false;
        }

        return true;

    }

    //
    // Ensure both with and without trailing slash for domain-only URIs
    // Postel's Law" or the Robustness Principle is being applied here.
    // "Be conservative in what you send, be liberal in what you accept."
    // — Jon Postel, RFC 761 (Transmission Control Protocol, 1981)
    //
    private static void DenormalizeSubjectAltNames(List<string>? subjectAltNames)
    {
        if (subjectAltNames != null)
        {
            var additionalNames = new HashSet<string>();
            foreach (var name in subjectAltNames)
            {
                if (Uri.TryCreate(name, UriKind.Absolute, out var uri))
                {
                    if (string.IsNullOrEmpty(uri.AbsolutePath) || uri.AbsolutePath == "/")
                    {
                        var withSlash = uri.GetLeftPart(UriPartial.Authority) + "/";
                        var withoutSlash = uri.GetLeftPart(UriPartial.Authority);
                        if (!subjectAltNames.Contains(withSlash))
                            additionalNames.Add(withSlash);
                        if (!subjectAltNames.Contains(withoutSlash))
                            additionalNames.Add(withoutSlash);
                    }
                }
            }
            subjectAltNames.AddRange(additionalNames);
        }
    }

    private async Task<TokenValidationResult> ValidateToken(
        UdapMetadata udapServerMetaData,
        JsonWebTokenHandler tokenHandler,
        string[]? subjectAltNames,
        JsonWebToken? jwt)
    {
        var publicKey = _publicCertificate?.PublicKey.GetRSAPublicKey();

        if (publicKey != null)
        {
            var validatedToken = await tokenHandler.ValidateTokenAsync(
                udapServerMetaData.SignedMetadata,
                new TokenValidationParameters
                {
                    RequireSignedTokens = true,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuers =
                        subjectAltNames, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                    ValidateAudience = false, // No aud for UDAP metadata
                    ValidateLifetime = true,
                    IssuerSigningKey = new RsaSecurityKey(publicKey),
                    ValidAlgorithms = [jwt!.GetHeaderValue<string>(JwtHeaderParameterNames.Alg)], //must match signing algorithm
                });

            return validatedToken;
        }
        else
        {
            var ecdsaPublicKey = _publicCertificate?.PublicKey.GetECDsaPublicKey();

            var validatedToken = await tokenHandler.ValidateTokenAsync(
                udapServerMetaData.SignedMetadata,
                new TokenValidationParameters
                {
                    RequireSignedTokens = true,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuers =
                        subjectAltNames, //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                    ValidateAudience = false, // No aud for UDAP metadata
                    ValidateLifetime = true,
                    IssuerSigningKey = new ECDsaSecurityKey(ecdsaPublicKey),
                    ValidAlgorithms = [jwt!.GetHeaderValue<string>(JwtHeaderParameterNames.Alg)], //must match signing algorithm
                });

            return validatedToken;
        }
    }

    /// <summary>
    /// Validates the X.509 trust chain of the server's signing certificate using the trust anchor store registered in DI.
    /// </summary>
    /// <param name="community">An optional UDAP community identifier used to select the appropriate trust anchors.</param>
    /// <returns><c>true</c> if the certificate chains to a trusted anchor; otherwise <c>false</c>.</returns>
    public virtual Task<bool> ValidateTrustChain(string? community)
    {
        return ValidateTrustChain(community, null);
    }

    /// <summary>
    /// Validates the X.509 trust chain of the server's signing certificate, optionally using a client-supplied trust anchor store.
    /// </summary>
    /// <param name="community">An optional UDAP community identifier used to select the appropriate trust anchors.</param>
    /// <param name="clientSuppliedTrustAnchorStore">An explicit trust anchor store; when null, falls back to the store registered in DI.</param>
    /// <returns><c>true</c> if the certificate chains to a trusted anchor; otherwise <c>false</c>.</returns>
    public virtual async Task<bool> ValidateTrustChain(string? community, ITrustAnchorStore? clientSuppliedTrustAnchorStore)
    {
        if (_publicCertificate == null)
        {
            throw new UnauthorizedAccessException("Failed Trust Chain Validation: Missing public certificate");
        }

        var store = clientSuppliedTrustAnchorStore != null ? 
            await clientSuppliedTrustAnchorStore.Resolve()
            : (_trustAnchorStore == null ? null : await _trustAnchorStore.Resolve());

        var anchors = X509Certificate2Collection(community, store).ToList();

        if (anchors.Count == 0)
        {
            _logger.LogWarning($"{nameof(UdapClient)} does not contain any anchor certificates");
            return false;
        }

        var anchorCertificates = anchors.ToX509Collection();

        if (anchorCertificates == null || !anchorCertificates.Any())
        {
            _logger.LogWarning($"{nameof(UdapClient)} does not contain any anchor certificates");
            return false;
        }

        return await _trustChainValidator.IsTrustedCertificateAsync(
            nameof(UdapClient),
            _publicCertificate,
            anchors.SelectMany(a =>
                    a.Intermediates == null
                        ? Enumerable.Empty<X509Certificate2>()
                        : a.Intermediates.Select(i => X509Certificate2.CreateFromPem(i.Certificate)))
                .ToArray().ToX509Collection(),
            anchorCertificates);
    }

    private static IEnumerable<Anchor> X509Certificate2Collection(string? community, ITrustAnchorStore? store)
    {
        IEnumerable<Anchor> anchorCertificates;

        if (store == null)
        {
            return Enumerable.Empty<Anchor>();
        }

        if (community != null && store.AnchorCertificates.Any(a => a.Community != null))
        {
            anchorCertificates = store.AnchorCertificates
                .Where(a => a.Community == community)
                .Select(a => a);
        }
        else
        {
            anchorCertificates = store.AnchorCertificates;
        }

        return anchorCertificates;
    }

    private void NotifyTokenError(string message)
    {
        _logger.LogWarning("Token error: {Message}", message.Replace(Environment.NewLine, ""));

        if (TokenError != null)
        {
            try
            {
                TokenError(message);
            }
            catch
            {
                // ignored
            }
        }
    }
}
