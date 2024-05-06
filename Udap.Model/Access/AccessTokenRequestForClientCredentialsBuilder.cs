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
using System.Text.Json;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;
using Udap.Model.Statement;
using Udap.Model.UdapAuthenticationExtensions;

namespace Udap.Model.Access;

/// <summary>
/// 
/// </summary>
public  class AccessTokenRequestForClientCredentialsBuilder
{
    
    private List<Claim> _claims;
    private string? _tokenEndoint;
    private string? _clientId;
    private DateTime _now;
    private X509Certificate2 _certificate;
    private string? _scope;

    private AccessTokenRequestForClientCredentialsBuilder(string? clientId, string? tokenEndpoint, X509Certificate2 certificate)
    {
        _now = DateTime.UtcNow.ToUniversalTime();
        _tokenEndoint = tokenEndpoint;
        _clientId = clientId;
        _certificate = certificate;

        _claims = new List<Claim>
        {
            new Claim(JwtClaimTypes.Subject, _clientId),
            new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(_now).ToString(), ClaimValueTypes.Integer),
            new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
            // new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
        };
    }

    public static AccessTokenRequestForClientCredentialsBuilder Create(string? clientId, string? tokenEndpoint, X509Certificate2 certificate)
    {
        return new AccessTokenRequestForClientCredentialsBuilder(clientId, tokenEndpoint, certificate);
    }
    
    /// <summary>
    /// Add more claims
    /// </summary>
    /// <param name="claim"></param>
    /// <returns></returns>
    public AccessTokenRequestForClientCredentialsBuilder WithClaim(Claim claim)
    {
        _claims.Add(claim);
        return this;
    }

    public AccessTokenRequestForClientCredentialsBuilder WithScope(string scope)
    {
        _scope = scope;
        return this;
    }

    // private string BuildHl7B2BExtensions()
    // {
    //     return "{\"version\": \"1\", \"subject_name\": \"todo.  more work to do here\"}";
    // }

    private Dictionary<string, B2BAuthorizationExtension>? _extensions;
    
    public AccessTokenRequestForClientCredentialsBuilder WithExtension(string key, B2BAuthorizationExtension value)
    {
        //TODO: Hack for connect-a-thon.
        if (_extensions == null)
        {
            _extensions = new Dictionary<string, B2BAuthorizationExtension>();
        }

        _extensions[key] = value;
        
        return this;
    }

    /// <summary>
    /// Build an <see cref="UdapClientCredentialsTokenRequest"/>
    /// </summary>
    /// <param name="algorithm"></param>
    /// <returns></returns>
    public UdapClientCredentialsTokenRequest Build(string? algorithm = UdapConstants.SupportedAlgorithm.RS256)
    {
        var clientAssertion = BuildClientAssertion(algorithm);

        return new UdapClientCredentialsTokenRequest
        {
            Address = _tokenEndoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new IdentityModel.Client.ClientAssertion()
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = _scope,
        };
    }
    

    private string BuildClientAssertion(string algorithm)
    {
        JwtPayLoadExtension jwtPayload;
        
        //HL7 FHIR IG profile
        jwtPayload = new JwtPayLoadExtension(
            _clientId, //TODO:: Let user pick the subject alt name.  Create will need extra param.
            _tokenEndoint, //The FHIR Authorization Server's token endpoint URL
            _claims,
            _now,
            _now.AddMinutes(5)
        );

        if (_extensions != null)
        {
            var payload = jwtPayload as Dictionary<string, object>;
            payload.Add(UdapConstants.JwtClaimTypes.Extensions, _extensions);
        }
        
        Console.WriteLine(JsonSerializer.Serialize(jwtPayload, new JsonSerializerOptions{WriteIndented = true}));

        return SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(_certificate, jwtPayload)
                .Build(algorithm);
    }
}