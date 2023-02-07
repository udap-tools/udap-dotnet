#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace Udap.Server.Hosting;
public class UdapAuthorizationResponseMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<UdapAuthorizationResponseMiddleware> _logger;

    public UdapAuthorizationResponseMiddleware(RequestDelegate next, ILogger<UdapAuthorizationResponseMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
            if (context.Request.Path.Value != null && context.Request.Path.Value.Contains("connect/token"))
            {
                if (context.Response.Headers.ContentType.ToString().ToLower().Equals("application/json; charset=utf-8"))
                {
                    context.Response.Headers.Remove("Content-Type");
                    context.Response.Headers.Add("Content-Type", new StringValues("application/json"));

                    _logger.LogDebug("Changed Content-Type header to \"application/json\"");
                }
            }

            return Task.FromResult(0);
        });

        await _next(context);
    }
}
