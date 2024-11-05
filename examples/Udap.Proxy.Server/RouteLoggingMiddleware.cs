#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Proxy.Server;

public class RouteLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RouteLoggingMiddleware> _logger;

    public RouteLoggingMiddleware(RequestDelegate next, ILogger<RouteLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var endpoint = context.GetEndpoint();
        if (endpoint != null)
        {
            var routeName = endpoint.DisplayName;
            if (!string.IsNullOrEmpty(routeName))
            {
                _logger.LogInformation($"Route matched: {routeName}");
            }
        }

        await _next(context);
    }
}
