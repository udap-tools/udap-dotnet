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
using IdentityModel;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Udap.Common.Certificates;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Util.Extensions;

namespace Udap.Metadata.Server;

public class UdapMetaDataBuilder
{
    private UdapMetadata _udapMetadata;
    private readonly IPrivateCertificateStore _certificateStore;
    private readonly ILogger<UdapMetaDataBuilder> _logger;


    public UdapMetaDataBuilder(
        UdapMetadata udapMetadata,
        IPrivateCertificateStore certificateStore,
        ILogger<UdapMetaDataBuilder> logger)
    {
        _udapMetadata = udapMetadata;
        _certificateStore = certificateStore;
        _logger = logger;
    }

    public ICollection<string> GetCommunities()
    {
        return _udapMetadata.Communities();
    }

    public string GetCommunitiesAsHtml(string path)
    {
        return _udapMetadata.CommunitiesAsHtml(path);
    }

    /// <summary>
    /// Essentials: OAuth 2.0 Authorization Server Metadata:: https://datatracker.ietf.org/doc/html/rfc8414#section-2.1
    /// Further restrained by UDAP IG:: http://hl7.org/fhir/us/udap-security/discovery.html#signed-metadata-elements 
    /// </summary>
    /// <returns></returns>
    /// <exception cref="NotImplementedException"></exception>
    public async Task<UdapMetadata?> SignMetaData(string baseUrl, string? community, CancellationToken token = default)
    {
        var udapMetaData = _udapMetadata.Clone();
        var udapMetadataConfig = udapMetaData.GetUdapMetadataConfig(community);

        if (udapMetadataConfig == null)
        {
            _logger.LogWarning($"Missing metadata for community: {System.Web.HttpUtility.UrlEncode(community)}");
            return null;
        }

        udapMetaData.AuthorizationEndpoint = udapMetadataConfig.SignedMetadataConfig.AuthorizationEndpoint;
        udapMetaData.TokenEndpoint = udapMetadataConfig.SignedMetadataConfig.TokenEndpoint;
        udapMetaData.RegistrationEndpoint = udapMetadataConfig.SignedMetadataConfig.RegistrationEndpoint;

        if (udapMetadataConfig.SignedMetadataConfig.RegistrationSigningAlgorithms.Any())
        {
            udapMetaData.RegistrationEndpointJwtSigningAlgValuesSupported = udapMetadataConfig.SignedMetadataConfig.RegistrationSigningAlgorithms;
        }

        if (udapMetadataConfig.SignedMetadataConfig.TokenSigningAlgorithms.Any())
        {
            udapMetaData.TokenEndpointAuthSigningAlgValuesSupported = udapMetadataConfig.SignedMetadataConfig.TokenSigningAlgorithms;
        }

        var certificate = await Load(udapMetadataConfig);

        if (certificate == null)
        {
            _logger.LogWarning($"Missing default community certificate: {System.Web.HttpUtility.UrlEncode(community)}");
            return null;
        }

        var now = DateTime.UtcNow;

        var (iss, sub) = ResolveIssuer(baseUrl, udapMetadataConfig, certificate);

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

        if (udapMetaData.RegistrationEndpointJwtSigningAlgValuesSupported.First().IsECDSA())
        {
            udapMetaData.SignedMetadata = builder.BuildECDSA(udapMetaData.
                RegistrationEndpointJwtSigningAlgValuesSupported.First());
        }
        else
        {
            udapMetaData.SignedMetadata = builder.Build(udapMetaData.
                RegistrationEndpointJwtSigningAlgValuesSupported.First());
        }

        return udapMetaData;
    }

    private (string issuer, string subject) ResolveIssuer(string baseUrl, UdapMetadataConfig udapMetadataConfig, X509Certificate2 certificate)
    {
        var issuer = udapMetadataConfig.SignedMetadataConfig.Issuer;
        var subject = udapMetadataConfig.SignedMetadataConfig.Subject;
        var autoIss = certificate.ResolveUriSubjAltName(baseUrl);

        if (string.IsNullOrEmpty(issuer))
        {
            issuer = autoIss;
        }

        if (string.IsNullOrEmpty(subject))
        {
            subject = autoIss;
        }

        return (issuer, subject);
    }

    private async Task<X509Certificate2?> Load(UdapMetadataConfig udapMetadataConfig)
    {
        var store = await _certificateStore.Resolve();

        var entity = store.IssuedCertificates
            .Where(c => c.Community == udapMetadataConfig.Community)
            .MaxBy(c => c.Certificate!.NotBefore);

        if (entity == null)
        {
            _logger.LogInformation($"Missing certificate for community: {udapMetadataConfig.Community}");
            return null;
        }

        return entity.Certificate;
    }
}