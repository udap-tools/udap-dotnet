using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Udap.Client.Client;
using Udap.Server.Configuration;

namespace Udap.Server.Hosting;

internal class UdapTieredOAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IdentityServerOptions _options;
    private readonly IUdapClient _udapClient;
    private readonly ILogger<UdapTokenResponseMiddleware> _logger;

    public UdapTieredOAuthMiddleware(
        RequestDelegate next,
        IdentityServerOptions options,
        IUdapClient udapClient,
        ILogger<UdapTokenResponseMiddleware> logger)
    {
        _next = next;
        _options = options;
        _udapClient = udapClient;
        _logger = logger;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="context"></param>
    /// <param name="clients"></param>
    /// <param name="udapServerOptions"></param>
    /// <param name="interactionService"></param>
    /// <returns></returns>
    public async Task Invoke(
        HttpContext context,
        IClientStore clients,
        ServerSettings udapServerOptions,
        IIdentityServerInteractionService interactionService)
    {
        if (context.Request.Path.Value != null &&
            context.Request.Path.Value.Contains(Constants.ProtocolRoutePaths.Authorize))
        {
            var requestParams = context.Request.Query;

            if (requestParams.Any())
            {
                if (requestParams.TryGetValue("idp", out var idp))
                {
                    // if idp is present, then this is a Tiered OAuth request.

                    // Validate idp Server;
                    var response = await _udapClient.ValidateResource(idp);

                    if (response.IsError)
                    {
                        _logger.LogError(response.Error);
                    }
                    else
                    {
                        _logger.LogInformation(JsonSerializer.Serialize(
                            _udapClient.UdapServerMetaData,
                            new JsonSerializerOptions { WriteIndented = true }));
                    }

                    // if not registered then register.


                    // redirect

                    var location = BuildTieredOAuthRedirectUrl(idp, requestParams);
                    context.Response.Redirect(location, false);

                    return;
                }
            }
        }

        await _next(context);

    }

    private string BuildTieredOAuthRedirectUrl(StringValues idp, IQueryCollection requestParams)
    {
        if (idp.Count > 1)
        {
            throw new ArgumentException("Only one idp is supported", nameof(idp));
        }

        var uri = idp + "/connect/authorize?" + requestParams
            .Where(param => param.Key != "idp")
            .Select(param => $"{param.Key}={param.Value}")
            .Aggregate((current, next) => $"{current}&{next}");

        return uri;
    }
}