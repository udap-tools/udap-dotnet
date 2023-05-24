#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Udap.Common.Extensions;
using Udap.Metadata.Server;
using Udap.Model;
using Vonk.Core.Context;
using Vonk.Core.Context.Http;
using Vonk.Core.Pluggability;

namespace Udap.Metadata.Vonk.Server;


[VonkConfiguration(order: 1201)]
public static class UdapConfiguration
{
    public static IServiceCollection AddUdapWellKnownServices(this IServiceCollection services,
        IConfiguration configuration)
    {
        return services.AddUdapMetadataServer(configuration);
    }

    // public static IApplicationBuilder UseUdapWellKnownEndpoints(this WebApplication app)
    // {
    //     return app.UseUdapMetadataServer();
    // }

    public static IApplicationBuilder UseUdaptWellKnownEndpoints(this IApplicationBuilder app)
    {
        var enabled = app.ApplicationServices.GetRequiredService<IOptions<UdapMetadataOptions>>()?.Value.Enabled ?? false;
        if (!enabled)
            return app;

        var routeBuilder = new RouteBuilder(app);
        routeBuilder.MapMiddlewareGet(".well-known/udap",
            appBuilder => appBuilder.UseMiddleware<UdapPluginMiddleware>());
        routeBuilder.MapMiddlewareGet(".well-known/udap/communities",
            appBuilder => appBuilder.UseMiddleware<UdapPluginMiddlewareCommunities>());
        routeBuilder.MapMiddlewareGet(".well-known/udap/communities/ashtml",
            appBuilder => appBuilder.UseMiddleware<UdapPluginMiddlewareCommunitiesAsHtml>());
        var routes = routeBuilder.Build();
        return app.UseRouter(routes);
    }
}

public class UdapPluginMiddleware
{
    private readonly RequestDelegate _next;
    private readonly UdapMetaDataBuilder _udapMetadataBuilder;

    public UdapPluginMiddleware(RequestDelegate next, UdapMetaDataBuilder udapMetadataBuilder)
    {
        _next = next;
        _udapMetadataBuilder = udapMetadataBuilder;
    }

    public async Task Invoke(HttpContext httpContext)
    {
        var vonkContext = httpContext.Vonk();
        var (request, args, _) = vonkContext.Parts();

        if (await _udapMetadataBuilder.SignMetaData(
                httpContext.Request.GetDisplayUrl().GetBaseUrlFromMetadataUrl(),
                null,
                default)
            is { } udapMetadata)
        {
            var response = udapMetadata.SerializeToJson();
            var contentLength = Encoding.UTF8.GetByteCount(response).ToString();

            httpContext.Response.Headers.Add("Content-Type", "application/json; charset=utf-8");
            httpContext.Response.Headers.Add("Content-Length", contentLength);
            httpContext.Response.StatusCode = 200;
            await httpContext.Response.WriteAsync(response);
            return;
        }

        httpContext.Response.StatusCode = (int)HttpStatusCode.NotFound;
        
    }
}

public class UdapPluginMiddlewareCommunities
{
    private readonly RequestDelegate _next;
    private readonly UdapMetaDataBuilder _udapMetadataBuilder;

    public UdapPluginMiddlewareCommunities(RequestDelegate next, UdapMetaDataBuilder udapMetadataBuilder)
    {
        _next = next;
        _udapMetadataBuilder = udapMetadataBuilder;
    }

    public async Task Invoke(HttpContext httpContext)
    {
        var response = JsonSerializer.Serialize(_udapMetadataBuilder.GetCommunities());
        var contentLength = Encoding.UTF8.GetByteCount(response).ToString();

        httpContext.Response.Headers.Add("Content-Type", "application/json; charset=utf-8");
        httpContext.Response.Headers.Add("Content-Length", contentLength);
        httpContext.Response.StatusCode = 200;
        await httpContext.Response.WriteAsync(response);
    }
}

public class UdapPluginMiddlewareCommunitiesAsHtml
{
    private readonly RequestDelegate _next;
    private readonly UdapMetaDataBuilder _udapMetadataBuilder;

    public UdapPluginMiddlewareCommunitiesAsHtml(RequestDelegate next, UdapMetaDataBuilder udapMetadataBuilder)
    {
        _next = next;
        _udapMetadataBuilder = udapMetadataBuilder;
    }

    public async Task Invoke(HttpContext httpContext)
    {
        var response = _udapMetadataBuilder.GetCommunitiesAsHtml(httpContext.Request.GetDisplayUrl().GetBaseUrlFromMetadataUrl());
        var contentLength = Encoding.UTF8.GetByteCount(response).ToString();

        httpContext.Response.Headers.Add("Content-Type", "text/html; charset=utf-8");
        httpContext.Response.Headers.Add("Content-Length", contentLength);
        httpContext.Response.StatusCode = 200;
        await httpContext.Response.WriteAsync(response);
    }
}
