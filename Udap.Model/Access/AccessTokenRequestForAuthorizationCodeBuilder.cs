#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using Udap.Model.Statement;

namespace Udap.Model.Access;

/// <summary>
/// 
/// </summary>
public class AccessTokenRequestForAuthorizationCodeBuilder
{

    private readonly List<Claim> _claims;
    private readonly string? _tokenEndpoint;
    private readonly string? _clientId;
    private readonly string? _code;
    private readonly string? _redirectUri;
    private readonly DateTime _now;
    private readonly X509Certificate2 _certificate;

    private AccessTokenRequestForAuthorizationCodeBuilder(string? clientId, string? tokenEndpoint, X509Certificate2 certificate, string? redirectUri, string? code)
    {
        _now = DateTime.UtcNow.ToUniversalTime();
        _tokenEndpoint = tokenEndpoint;
        _clientId = clientId;
        _certificate = certificate;
        _code = code;
        _redirectUri = redirectUri;

        
            _claims =
            [
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(_now).ToString(), ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId())
                // new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            ];

            if (_clientId != null)
            {
                _claims.Add(new Claim(JwtClaimTypes.Subject, _clientId));
            }
    }

    public static AccessTokenRequestForAuthorizationCodeBuilder Create(string? clientId, string? tokenEndpoint, X509Certificate2 certificate, string? redirectUri, string? code)
    {
        return new AccessTokenRequestForAuthorizationCodeBuilder(clientId, tokenEndpoint, certificate, redirectUri, code);
    }

    /// <summary>
    /// Add more claims
    /// </summary>
    /// <param name="claim"></param>
    /// <returns></returns>
    public AccessTokenRequestForAuthorizationCodeBuilder WithClaim(Claim claim)
    {
        _claims.Add(claim);
        return this;
    }

    /// <summary>
    /// Build an <see cref="UdapAuthorizationCodeTokenRequest"/>
    /// </summary>
    /// <param name="algorithm"></param>
    /// <returns></returns>
    public UdapAuthorizationCodeTokenRequest Build(string? algorithm = UdapConstants.SupportedAlgorithm.RS256)
    {
        var clientAssertion = BuildClientAssertion(algorithm);

        return new UdapAuthorizationCodeTokenRequest()
        {
            Address = _tokenEndpoint ?? throw new InvalidOperationException("TokenEndpoint cannot be null"),
            RequestUri = new Uri(_tokenEndpoint), //TODO
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            Code = _code ?? throw new InvalidOperationException("Code cannot be null"),
            RedirectUri = _redirectUri ?? throw new InvalidOperationException("RedirectUri cannot be null"),
            ClientAssertion = new ClientAssertion
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion ?? throw new InvalidOperationException("ClientAssertion value cannot be null"),
            },
            Udap = UdapConstants.UdapVersionsSupportedValue
        };
    }

    private string BuildClientAssertion(string? algorithm)
    {
        var jwtPayload = new JwtPayLoadExtension(
            _clientId,
            _tokenEndpoint, //The FHIR Authorization Server's token endpoint URL
            _claims,
            _now,
            _now.AddMinutes(5)
        );

        return SignedSoftwareStatementBuilder<JwtPayLoadExtension>
            .Create(_certificate, jwtPayload)
            .Build(algorithm);
    }
}