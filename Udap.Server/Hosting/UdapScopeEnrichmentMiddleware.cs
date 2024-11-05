﻿#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Stores;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Udap.Common.Extensions;
using Udap.Server.Configuration;
using Udap.Util.Extensions;

namespace Udap.Server.Hosting;

internal class UdapScopeEnrichmentMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ServerSettings _udapServerOptions;
    private readonly ILogger<UdapScopeEnrichmentMiddleware> _logger;

    public UdapScopeEnrichmentMiddleware(
        RequestDelegate next,
        ServerSettings udapServerOptions,
        ILogger<UdapScopeEnrichmentMiddleware> logger)
    {
        _next = next;
        _udapServerOptions = udapServerOptions;
        _logger = logger;
    }

    public async Task Invoke(
        HttpContext context,
        IClientStore clients)
    {
        if (
            context.Request.Path.Value != null &&
            context.Request.Path.Value.Contains(Constants.ProtocolRoutePaths.Token))
        {
            var body = await context.Request.ReadFormAsync();

            if (body.Count != 0)
            {

                var clientAssertionType = body[OidcConstants.TokenRequest.ClientAssertionType].FirstOrDefault();
                var clientAssertion = body[OidcConstants.TokenRequest.ClientAssertion].FirstOrDefault();

                if (clientAssertion != null
                    && clientAssertion.IsPresent()
                    && clientAssertionType == OidcConstants.ClientAssertionTypes.JwtBearer)
                {
                    var clientId = GetClientIdFromToken(clientAssertion);

                    if (clientId == null || !clientId.IsPresent())
                    {
                        _logger.LogWarning("Could not find client_id in client assertion");
                        await _next(context);
                        return;
                    }

                    var client = await clients.FindClientByIdAsync(clientId);

                    if (client == null)
                    {
                        _logger.LogWarning("ClientId {ClientId} not found", clientId);
                    }
                    else
                    {
                        var defaultScopes = _udapServerOptions.DefaultSystemScopes?.Split(' ',
                            StringSplitOptions.RemoveEmptyEntries);

                        if (client.ClientSecrets.All(s =>
                                s.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME))
                        {
                            var form = (await context.Request.ReadFormAsync()).AsNameValueCollection();
                            if (!string.IsNullOrEmpty(form.Get("scope")))
                            {
                                _logger.LogDebug($"Skip appending scopes.");
                                await _next(context);
                                return;
                            }

                            var scopes = client.AllowedScopes;

                            //
                            // Default scopes only added if we have none.
                            //
                            if (defaultScopes != null && client.AllowedScopes.Count == 0)
                            {
                                foreach (var defaults in defaultScopes)
                                {
                                    scopes.Add(defaults);
                                }
                            }

                            _logger.LogDebug("Appending scopes; {Scopes}", scopes.ToSpaceSeparatedString());

                            form.Set(OidcConstants.TokenRequest.Scope, scopes.ToSpaceSeparatedString());
                            var values = new Dictionary<string, StringValues>();

                            foreach (var key in form.AllKeys)
                            {
                                if (key != null)
                                {
                                    values.Add(key, form.Get(key));
                                }
                            }

                            var formCol = new FormCollection(values);
                            context.Request.Form = formCol;
                        }
                    }
                }
            }
        }
        await _next(context);
    }
    private string? GetClientIdFromToken(string token)
    {
        try
        {
            var jwt = new JwtSecurityToken(token);
            return jwt.Subject;
        }
        catch (Exception e)
        {
            _logger.LogWarning(e, "Could not parse client assertion");
            return null;
        }
    }
}

