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
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Udap.Model.Access;

/// <summary>
/// 
/// </summary>
public  class AccessTokenRequestBuilder
{
    
    private List<Claim> _claims;
    private string _tokenEndoint;
    private string _clientId;
    private DateTime _now;
    private SigningCredentials _signingCredentials;
    private string _clientCertAsBase64;

    private AccessTokenRequestBuilder(string clientId, string tokenEndpoint, X509Certificate2 certificate)
    {
        _now = DateTime.UtcNow.ToUniversalTime();
        _tokenEndoint = tokenEndpoint;
        _clientId = clientId;
        _clientCertAsBase64 = Convert.ToBase64String(certificate.Export(X509ContentType.Cert));

        _claims = new List<Claim>
        {
            new Claim(JwtClaimTypes.Subject, _clientId),
            new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(_now).ToString(), ClaimValueTypes.Integer),
            new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
            // new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
        };
        
        var securityKey = new X509SecurityKey(certificate);
        _signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);
    }

    public static AccessTokenRequestBuilder Create(string clientId, string tokenEndpoint, X509Certificate2 certificate)
    {
        return new AccessTokenRequestBuilder(clientId, tokenEndpoint, certificate);
    }

    /// <summary>
    /// Add more claims
    /// </summary>
    /// <param name="claim"></param>
    /// <returns></returns>
    public AccessTokenRequestBuilder WithClaim(Claim claim)
    {
        _claims.Add(claim);
        return this;
    }

    public UdapClientCredentialsTokenRequest Build()
    {
        var clientAssertion = BuildClientAssertion();

        return new UdapClientCredentialsTokenRequest
        {
            Address = _tokenEndoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue
        };
    }

    private string BuildClientAssertion()
    {
        var jwtPayload = new JwtPayload(
            _clientId,
                _tokenEndoint, //The FHIR Authorization Server's token endpoint URL
                _claims,
                _now,
                _now.AddMinutes(5)
            );

        var jwtHeader = new JwtHeader
        {
            { "alg", _signingCredentials.Algorithm },
            { "x5c", new[] { _clientCertAsBase64 } }
        };

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedClientAssertion = jwtPayload.Base64UrlEncode();
        var encodedSignature = JwtTokenUtilities.CreateEncodedSignature(
            string.Concat(encodedHeader, ".", encodedClientAssertion), _signingCredentials);

        return string.Concat(encodedHeader, ".", encodedClientAssertion, ".", encodedSignature);
    }

    // private string BuildHl7B2BExtensions()
    // {
    //     return "{\"version\": \"1\", \"subject_name\": \"todo.  more work to do here\"}";
    // }
}
