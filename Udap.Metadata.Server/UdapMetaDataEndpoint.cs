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
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Udap.Common;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;

namespace Udap.Metadata.Server;

public class UdapMetaDataEndpoint
{
    private readonly ILogger<UdapMetaDataEndpoint> _logger;
    private readonly UdapMetaDataBuilder _metaDataBuilder;

    public UdapMetaDataEndpoint(UdapMetaDataBuilder metaDataBuilder, ILogger<UdapMetaDataEndpoint> logger)
    {
        _metaDataBuilder = metaDataBuilder;
        _logger = logger;
    }

    public async Task<IResult?> Process(string? community, CancellationToken token)
    {
        return await _metaDataBuilder.SignMetaData(community, token)
            is { } udapMetadata
            ? Results.Ok(udapMetadata)
            : Results.NotFound();
    }

    
    public IResult GetCommunities()
    {
        return Results.Ok(_metaDataBuilder.GetCommunities());
    }

    
    public IResult GetCommunitiesAsHtml(HttpContext httpContext)
    {
        var html = _metaDataBuilder.GetCommunitiesAsHtml(httpContext.Request.PathBase);
        httpContext.Response.ContentType = "text/html";
        
        return Results.Content(html);
    }
}

public class UdapMetaDataBuilder
{
    private readonly UdapMetadata _udapMetadata;
    private readonly ICertificateStore _certificateStore;
    private readonly ILogger<UdapMetaDataBuilder> _logger;


    public UdapMetaDataBuilder(
        UdapMetadata udapMetadata,
        ICertificateStore certificateStore,
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
    public async Task<UdapMetadata?> SignMetaData(string? community, CancellationToken token = default)
    {
        var udapMetadataConfig = _udapMetadata.GetUdapMetadataConfig(community);

        _udapMetadata.AuthorizationEndpoint = udapMetadataConfig?.SignedMetadataConfig.AuthorizationEndpoint;
        _udapMetadata.TokenEndpoint = udapMetadataConfig?.SignedMetadataConfig.TokenEndpoint;
        _udapMetadata.RegistrationEndpoint = udapMetadataConfig?.SignedMetadataConfig.RegistrationEndpoint;

        if (udapMetadataConfig != null)
        {
            var cert = await Load(udapMetadataConfig, token);

            if (cert == null)
            {
                _logger.LogWarning($"Missing default community certificate: {community}");
                return null;
            }

            var now = DateTime.UtcNow;

            var jwtPayload = new JwtPayLoadExtension(
                new List<Claim>
                {
                    new Claim(JwtClaimTypes.Issuer, udapMetadataConfig.SignedMetadataConfig.Issuer),
                    new Claim(JwtClaimTypes.Subject, udapMetadataConfig.SignedMetadataConfig.Subject),
                    new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                    new Claim(JwtClaimTypes.Expiration, EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                    new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                    new Claim(UdapConstants.Discovery.AuthorizationEndpoint, udapMetadataConfig.SignedMetadataConfig.AuthorizationEndpoint),
                    new Claim(UdapConstants.Discovery.TokenEndpoint, udapMetadataConfig.SignedMetadataConfig.TokenEndpoint),
                    new Claim(UdapConstants.Discovery.RegistrationEndpoint, udapMetadataConfig.SignedMetadataConfig.RegistrationEndpoint)
                });

            var builder = SignedSoftwareStatementBuilder<ISoftwareStatementSerializer>.Create(cert, jwtPayload);

            _udapMetadata.SignedMetadata = builder.Build();

            return _udapMetadata;
        }

        _logger.LogWarning($"Missing metadata for community: {community}");
        return null;
    }

    private async Task<X509Certificate2?> Load(UdapMetadataConfig udapMetadataConfig, CancellationToken token)
    {
        var store = await _certificateStore.Resolve();

        var entity = store.IssuedCertificates
            .Where(c => c.Community == udapMetadataConfig.Community && c.Certificate != null)
            .MaxBy(c => c.Certificate!.NotBefore);

        if (entity == null)
        {
            _logger.LogInformation($"Missing certificate for community: {udapMetadataConfig.Community}");
            return null;
        }

        return entity.Certificate;
    }
}