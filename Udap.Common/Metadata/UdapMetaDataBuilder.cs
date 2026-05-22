#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Duende.IdentityModel;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Udap.Common.Certificates;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Util.Extensions;

namespace Udap.Common.Metadata;

/// <summary>
/// Builds and signs UDAP metadata documents for the <c>.well-known/udap</c> endpoint.
/// </summary>
/// <typeparam name="TUdapMetadataOptions">The metadata options type, must extend <see cref="UdapMetadataOptions"/>.</typeparam>
/// <typeparam name="TUdapMetadata">The metadata type, must extend <see cref="UdapMetadata"/>.</typeparam>
public class UdapMetaDataBuilder<TUdapMetadataOptions, TUdapMetadata>
    where TUdapMetadataOptions : UdapMetadataOptions
    where TUdapMetadata : UdapMetadata
{
    private readonly IUdapMetadataOptionsProvider _optionsProvider;
    private readonly IPrivateCertificateStore _certificateStore;
    private readonly ILogger<UdapMetaDataBuilder<TUdapMetadataOptions, TUdapMetadata>> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="UdapMetaDataBuilder{TUdapMetadataOptions, TUdapMetadata}"/>.
    /// </summary>
    /// <param name="optionsProvider">The provider for UDAP metadata options.</param>
    /// <param name="certificateStore">The certificate store containing signing certificates.</param>
    /// <param name="logger">The logger instance.</param>
    public UdapMetaDataBuilder(
        IUdapMetadataOptionsProvider optionsProvider,
        IPrivateCertificateStore certificateStore,
        ILogger<UdapMetaDataBuilder<TUdapMetadataOptions, TUdapMetadata>> logger)
    {
        _optionsProvider = optionsProvider;
        _certificateStore = certificateStore;
        _logger = logger;
    }

    /// <summary>
    /// List of community names
    /// </summary>
    /// <returns></returns>
    public ICollection<string> GetCommunities()
    {
        var options = _optionsProvider.Value;
        var udapMetaData = (TUdapMetadata)Activator.CreateInstance(typeof(TUdapMetadata), options)!;

        return udapMetaData.Communities();
    }

    /// <summary>
    /// List of community HTML Anchors.
    /// For communities with multiple certificates, generates per-SAN links
    /// filtered to only SANs matching the current host.
    /// </summary>
    /// <param name="path">Base URL.  The same as the UDAP subject alternative name. </param>
    /// <param name="token"></param>
    /// <returns></returns>
    public async Task<string> GetCommunitiesAsHtml(string path, CancellationToken token = default)
    {
        var options = _optionsProvider.Value;
        var udapMetaData = (TUdapMetadata)Activator.CreateInstance(typeof(TUdapMetadata), options)!;

        var store = await _certificateStore.Resolve(token);
        var pathUri = new Uri(path.TrimEnd('/'));
        var hostAuthority = $"{pathUri.Scheme}://{pathUri.Authority}";

        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html><head>");
        sb.AppendLine("<title>Supported UDAP Communities</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }");
        sb.AppendLine("  h1 { font-size: 1.4rem; border-bottom: 2px solid #0078d4; padding-bottom: 0.4rem; }");
        sb.AppendLine("  .community { margin-bottom: 1.2rem; }");
        sb.AppendLine("  .community-name { font-weight: 600; font-size: 1rem; margin-bottom: 0.3rem; }");
        sb.AppendLine("  .community a { display: inline-block; color: #0078d4; text-decoration: none; padding: 0.15rem 0; font-size: 0.9rem; }");
        sb.AppendLine("  .community a:hover { text-decoration: underline; }");
        sb.AppendLine("  .san-list { margin-left: 1.2rem; }");
        sb.AppendLine("</style>");
        sb.AppendLine("</head><body>");
        sb.AppendLine("<h1>Supported UDAP Communities</h1>");

        foreach (var community in udapMetaData.Communities())
        {
            var communityCerts = store.IssuedCertificates
                .Where(c => c.Community == community)
                .ToList();

            var matchingSans = communityCerts
                .SelectMany(c => c.SubjectAltNames)
                .Where(san => san.StartsWith(hostAuthority, StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(san => san)
                .ToList();

            sb.AppendLine("<div class=\"community\">");

            if (matchingSans.Count > 1)
            {
                sb.AppendLine($"  <div class=\"community-name\">{community}</div>");
                sb.AppendLine("  <div class=\"san-list\">");
                foreach (var san in matchingSans)
                {
                    var sanPath = san.TrimEnd('/');
                    var href = $"{sanPath}/.well-known/udap?community={community}";
                    sb.AppendLine($"    <a href=\"{href}\" target=\"_blank\">{sanPath}</a><br/>");
                }
                sb.AppendLine("  </div>");
            }
            else
            {
                var href = $"{path.TrimEnd('/')}/.well-known/udap?community={community}";
                sb.AppendLine($"  <a href=\"{href}\" target=\"_blank\">{community}</a>");
            }

            sb.AppendLine("</div>");
        }

        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    /// <summary>
    /// Essentials: OAuth 2.0 Authorization Server Metadata:: https://datatracker.ietf.org/doc/html/rfc8414#section-2.1
    /// Further restrained by UDAP IG:: http://hl7.org/fhir/us/udap-security/discovery.html#signed-metadata-elements 
    /// </summary>
    /// <returns></returns>
    /// <exception cref="System.NotImplementedException"></exception>
    public async Task<UdapMetadata?> SignMetaData(string baseUrl, string? community = null, CancellationToken token = default)
    {
        var options = _optionsProvider.Value;
        var udapMetaData = (TUdapMetadata)Activator.CreateInstance(typeof(TUdapMetadata), options)!;

        var udapMetadataConfig = udapMetaData.GetUdapMetadataConfig(community);

        if (udapMetadataConfig == null)
        {
            var sanitizedCommunity = community?.Replace("\r", "").Replace("\n", "");
            _logger.LogWarning("Missing metadata for community: {Community}", System.Net.WebUtility.UrlEncode(sanitizedCommunity));
            return null;
        }

        udapMetaData.AuthorizationEndpoint = udapMetadataConfig.SignedMetadataConfig.AuthorizationEndpoint;
        udapMetaData.TokenEndpoint = udapMetadataConfig.SignedMetadataConfig.TokenEndpoint;
        udapMetaData.RegistrationEndpoint = udapMetadataConfig.SignedMetadataConfig.RegistrationEndpoint;

        if (udapMetadataConfig.SignedMetadataConfig.RegistrationSigningAlgorithms != null && udapMetadataConfig.SignedMetadataConfig.RegistrationSigningAlgorithms.Count != 0)
        {
            udapMetaData.RegistrationEndpointJwtSigningAlgValuesSupported = udapMetadataConfig.SignedMetadataConfig.RegistrationSigningAlgorithms;
        }

        if (udapMetadataConfig.SignedMetadataConfig.TokenSigningAlgorithms != null && udapMetadataConfig.SignedMetadataConfig.TokenSigningAlgorithms.Count != 0)
        {
            udapMetaData.TokenEndpointAuthSigningAlgValuesSupported = udapMetadataConfig.SignedMetadataConfig.TokenSigningAlgorithms;
        }

        if (udapMetadataConfig.UdapCertificationsSupported != null && udapMetadataConfig.UdapCertificationsSupported.Count != 0)
        {
            udapMetaData.UdapCertificationsSupported = udapMetadataConfig.UdapCertificationsSupported;
        }

        if (udapMetadataConfig.UdapCertificationsRequired != null && udapMetadataConfig.UdapCertificationsRequired.Count != 0)
        {
            udapMetaData.UdapCertificationsRequired = udapMetadataConfig.UdapCertificationsRequired;
        }

        var certificate = await Load(udapMetadataConfig, baseUrl, token);

        if (certificate == null)
        {
            var sanitizedCommunity = System.Web.HttpUtility.UrlEncode(community)?.Replace(Environment.NewLine, "").Replace("\n", "").Replace("\r", "");
            _logger.LogWarning("Missing default community certificate: {Community}", sanitizedCommunity);
            return null;
        }

        var now = DateTime.UtcNow;

        var (iss, sub) = ResolveIssuer(baseUrl, certificate);

        var jwtPayload = new JwtPayLoadExtension(
            new List<Claim>
            {
                new Claim(JwtClaimTypes.Issuer, iss),
                new Claim(JwtClaimTypes.Subject, sub),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.Expiration, EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                new Claim(UdapConstants.Discovery.AuthorizationEndpoint, udapMetadataConfig.SignedMetadataConfig.AuthorizationEndpoint),
                new Claim(UdapConstants.Discovery.TokenEndpoint, udapMetadataConfig.SignedMetadataConfig.TokenEndpoint),
                new Claim(UdapConstants.Discovery.RegistrationEndpoint, udapMetadataConfig.SignedMetadataConfig.RegistrationEndpoint)
            });

        var builder = SignedSoftwareStatementBuilder<ISoftwareStatementSerializer>.Create(certificate, jwtPayload);

        if (udapMetaData.RegistrationEndpointJwtSigningAlgValuesSupported != null && udapMetaData.RegistrationEndpointJwtSigningAlgValuesSupported.First().IsECDSA())
        {
            udapMetaData.SignedMetadata = builder.BuildECDSA(udapMetaData.
                RegistrationEndpointJwtSigningAlgValuesSupported.First());
        }
        else
        {
            if (udapMetaData.RegistrationEndpointJwtSigningAlgValuesSupported != null)
            {
                udapMetaData.SignedMetadata =
                    builder.Build(udapMetaData.RegistrationEndpointJwtSigningAlgValuesSupported.First());
            }
        }

        return udapMetaData;
    }

    private static (string issuer, string subject) ResolveIssuer(string baseUrl, X509Certificate2 certificate)
    {
        var resolved = certificate.ResolveUriSubjAltName(baseUrl);

        return (resolved, resolved);
    }

    private async Task<X509Certificate2?> Load(UdapMetadataConfig udapMetadataConfig, string baseUrl, CancellationToken token)
    {
        var store = await _certificateStore.Resolve(token);
        var normalizedBaseUrl = new Uri(baseUrl.TrimEnd('/')).AbsoluteUri;

        var communityCerts = store.IssuedCertificates
            .Where(c => c.Community == udapMetadataConfig.Community)
            .ToList();

        var entity = communityCerts
            .Where(c => c.SubjectAltNames.Any(san =>
                san == baseUrl ||
                san == normalizedBaseUrl ||
                new Uri(san.TrimEnd('/')).AbsoluteUri == normalizedBaseUrl))
            .MaxBy(c => c.Certificate.NotBefore);

        // Fallback only when community has a single cert (backward compatibility)
        if (entity == null && communityCerts.Count == 1)
        {
            entity = communityCerts[0];
        }

        if (entity == null)
        {
            _logger.LogInformation("Missing certificate for community: {Community}", udapMetadataConfig.Community);
            return null;
        }

        return entity.Certificate;
    }
}