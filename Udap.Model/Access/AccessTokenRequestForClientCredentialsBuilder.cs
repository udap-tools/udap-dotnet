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
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;
using Udap.Model.Statement;

namespace Udap.Model.Access;

/// <summary>
/// 
/// </summary>
public  class AccessTokenRequestForClientCredentialsBuilder
{
    
    private readonly List<Claim> _claims;
    private readonly string? _tokenEndoint;
    private readonly string? _clientId;
    private readonly DateTime _now;
    private readonly X509Certificate2 _certificate;
    private string? _scope;
    private readonly Dictionary<string, object> _extensions = [];

    private AccessTokenRequestForClientCredentialsBuilder(string? clientId, string? tokenEndpoint, X509Certificate2 certificate)
    {
        _now = DateTime.UtcNow.ToUniversalTime();
        _tokenEndoint = tokenEndpoint;
        _clientId = clientId;
        _certificate = certificate;

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
    
    public AccessTokenRequestForClientCredentialsBuilder WithExtension<T>(string key, T value) where T : class
    {
        var jsonElement = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(value));
        _extensions[key] = jsonElement;
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
    

    private string BuildClientAssertion(string? algorithm)
    {
        var jwtPayload =
            //HL7 FHIR IG profile
            new JwtPayLoadExtension(
            _clientId, //TODO:: Let user pick the subject alt name.  Create will need extra param.
            _tokenEndoint,
            _claims,
            _now,
            _now.AddMinutes(5)
        );

        if (_extensions.Count != 0)
        {
            var payload = jwtPayload as Dictionary<string, object>;
            payload.Add(UdapConstants.JwtClaimTypes.Extensions, _extensions);
        }
        
        return SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(_certificate, jwtPayload)
                .Build(algorithm);
    }
}