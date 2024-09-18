﻿#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using IdentityModel;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Udap.Common.Certificates;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Util.Extensions;

namespace Udap.Common.Metadata;

public class UdapMetaDataBuilder<TUdapMetadataOptions, TUdapMetadata> 
    where TUdapMetadataOptions : UdapMetadataOptions
    where TUdapMetadata : UdapMetadata
{
    private readonly IOptionsMonitor<TUdapMetadataOptions> _optionsMonitor;
    private readonly IPrivateCertificateStore _certificateStore;
    private readonly ILogger<UdapMetaDataBuilder<TUdapMetadataOptions, TUdapMetadata>> _logger;

    public UdapMetaDataBuilder(
        IOptionsMonitor<TUdapMetadataOptions> optionsMonitor,
        IPrivateCertificateStore certificateStore,
        ILogger<UdapMetaDataBuilder<TUdapMetadataOptions, TUdapMetadata>> logger)
    {
        _optionsMonitor = optionsMonitor;
        _certificateStore = certificateStore;
        _logger = logger;
    }

    /// <summary>
    /// List of community names
    /// </summary>
    /// <returns></returns>
    public ICollection<string> GetCommunities()
    {
        var options = _optionsMonitor.CurrentValue;
        var udapMetaData = (TUdapMetadata)Activator.CreateInstance(typeof(TUdapMetadata), options)!;

        return udapMetaData.Communities();
    }

    /// <summary>
    /// List of community HTML Anchors
    /// </summary>
    /// <param name="path">Base URL.  The same as the UDAP subject alternative name. </param>
    /// <returns></returns>
    public string GetCommunitiesAsHtml(string path)
    {
        var options = _optionsMonitor.CurrentValue;
        var udapMetaData = (TUdapMetadata)Activator.CreateInstance(typeof(TUdapMetadata), options)!;

        return udapMetaData.CommunitiesAsHtml(path);
    }

    /// <summary>
    /// Essentials: OAuth 2.0 Authorization Server Metadata:: https://datatracker.ietf.org/doc/html/rfc8414#section-2.1
    /// Further restrained by UDAP IG:: http://hl7.org/fhir/us/udap-security/discovery.html#signed-metadata-elements 
    /// </summary>
    /// <returns></returns>
    /// <exception cref="System.NotImplementedException"></exception>
    public async Task<UdapMetadata?> SignMetaData(string baseUrl, string? community = null, CancellationToken token = default)
    {
        var options = _optionsMonitor.CurrentValue;
        var udapMetaData = (TUdapMetadata)Activator.CreateInstance(typeof(TUdapMetadata), options)!;

        var udapMetadataConfig = udapMetaData.GetUdapMetadataConfig(community);

        if (udapMetadataConfig == null)
        {
            _logger.LogWarning($"Missing metadata for community: {System.Net.WebUtility.UrlEncode(community)}");
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

        if (entity == null )
        {
            _logger.LogInformation($"Missing certificate for community: {udapMetadataConfig.Community}");
            return null;
        }

        return entity.Certificate;
    }
}