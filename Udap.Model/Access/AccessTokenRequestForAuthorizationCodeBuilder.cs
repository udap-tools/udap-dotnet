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
    private DateTime _now;
    private readonly X509Certificate2 _certificate;

    private AccessTokenRequestForAuthorizationCodeBuilder(string? clientId, string? tokenEndpoint, X509Certificate2 certificate, string? redirectUri, string? code)
    {
        _now = DateTime.UtcNow.ToUniversalTime();
        _tokenEndpoint = tokenEndpoint;
        _clientId = clientId;
        _certificate = certificate;
        _code = code;
        _redirectUri = redirectUri;
        
        _claims = new List<Claim>
        {
            new Claim(JwtClaimTypes.Subject, _clientId),
            new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(_now).ToString(), ClaimValueTypes.Integer),
            new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
            // new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
        };
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
    
    public UdapAuthorizationCodeTokenRequest Build()
    {
        var clientAssertion = BuildClientAssertion();

        return new UdapAuthorizationCodeTokenRequest()
        {
            Address = _tokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            Code = _code,
            RedirectUri = _redirectUri,
            ClientAssertion = new ClientAssertion
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue
        };
    }

    private string? BuildClientAssertion()
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
            .Build();
    }

    // private string BuildHl7B2BExtensions()
    // {
    //     return "{\"version\": \"1\", \"subject_name\": \"todo.  more work to do here\"}";
    // }
}