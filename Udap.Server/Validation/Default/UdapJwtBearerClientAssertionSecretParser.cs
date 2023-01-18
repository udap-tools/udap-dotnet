#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Validation;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Udap.Model;
using Udap.Server.Extensions;

namespace Udap.Server.Validation.Default;

public class UdapJwtBearerClientAssertionSecretParser : ISecretParser
{
    private readonly IdentityServerOptions _options;
    private readonly ILogger _logger;

    public UdapJwtBearerClientAssertionSecretParser(IdentityServerOptions options,
        ILogger<UdapJwtBearerClientAssertionSecretParser> logger)
    {
        _options = options;
        _logger = logger;
    }
    /// <summary>
    /// Returns the authentication method name that this parser implements
    /// </summary>
    /// <value>The authentication method.</value>
    public string AuthenticationMethod => Constants.EndpointAuthenticationMethods.UdapPkiJwt;

    /// <summary>
    /// Tries to find a secret on the context that can be used for authentication
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>
    /// A parsed secret
    /// </returns>
    public async Task<ParsedSecret> ParseAsync(HttpContext context)
    {
        _logger.LogDebug("Start parsing for JWT client assertion in post body");

        if (!context.Request.HasApplicationFormContentType())
        {
            _logger.LogDebug("Content type is not a form");
            return null;
        }

        var body = await context.Request.ReadFormAsync();

        _logger.LogDebug(JsonSerializer.Serialize(body));
        if (body != null)
        {
            var clientAssertionType = body[OidcConstants.TokenRequest.ClientAssertionType].FirstOrDefault();
            var clientAssertion = body[OidcConstants.TokenRequest.ClientAssertion].FirstOrDefault();

            if (clientAssertion != null
                && clientAssertion.IsPresent() 
                && clientAssertionType == OidcConstants.ClientAssertionTypes.JwtBearer)
            {
                if (clientAssertion.Length > _options.InputLengthRestrictions.Jwt)
                {
                    _logger.LogError("Client assertion token exceeds maximum length.");
                    return null;
                }

                var clientId = GetClientIdFromToken(clientAssertion);
                if (!clientId.IsPresent())
                {
                    return null;
                }

                if (clientId.Length > _options.InputLengthRestrictions.ClientId)
                {
                    _logger.LogError("Client ID exceeds maximum length.");
                    return null;
                }

                var parsedSecret = new ParsedSecret
                {
                    Id = clientId,
                    Credential = clientAssertion,
                    Type = IdentityServerConstants.ParsedSecretTypes.JwtBearer
                };

                return parsedSecret;
            }
        }

        _logger.LogDebug("No JWT client assertion found in post body");
        return null;
    }

    private string GetClientIdFromToken(string token)
    {
        try
        {
            var jwt = new JwtSecurityToken(token);
            return jwt.Subject;
        }
        catch (Exception e)
        {
            _logger.LogWarning("Could not parse client assertion", e);
            return null;
        }
    }

}