#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Udap.Server.Storage;

namespace Udap.Server.Hosting;


/// <summary>
/// https://groups.google.com/g/udap-discuss/c/jxgtlHOsg2A
/// </summary>
public class UdapTokenResponseMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<UdapTokenResponseMiddleware> _logger;

    public UdapTokenResponseMiddleware(RequestDelegate next, ILogger<UdapTokenResponseMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        var isTokenEndpoint = context.Request.Path.Value != null
                              && context.Request.Path.Value.Contains("connect/token");

        if (!isTokenEndpoint)
        {
            await _next(context);
            return;
        }

        var originalBody = context.Response.Body;

        using var bufferStream = new MemoryStream();
        context.Response.Body = bufferStream;

        await _next(context);

        bufferStream.Seek(0, SeekOrigin.Begin);
        var responseBody = await new StreamReader(bufferStream).ReadToEndAsync();

        var contentType = context.Response.Headers.ContentType.ToString();
        if (contentType.Equals("application/json; charset=utf-8", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Headers.Remove("Content-Type");
            context.Response.Headers.Append("Content-Type", new StringValues("application/json"));
            _logger.LogDebug("Changed Content-Type header to \"application/json\"");
        }

        if (context.Response.StatusCode is 400 or 401
            && !string.IsNullOrEmpty(responseBody))
        {
            var hasErrorDescription =
                context.Items.TryGetValue(UdapServerConstants.HttpContextItems.UdapErrorDescription, out var errorDescObj)
                && errorDescObj is string;

            var hasErrorExtensions =
                context.Items.TryGetValue(UdapServerConstants.HttpContextItems.UdapErrorExtensions, out var errorExtObj)
                && errorExtObj is Dictionary<string, object>;

            if (hasErrorDescription || hasErrorExtensions)
            {
                try
                {
                    using var doc = JsonDocument.Parse(responseBody);
                    var root = doc.RootElement;

                    if (root.ValueKind == JsonValueKind.Object)
                    {
                        // The stored description explains a failed client assertion, so it belongs only on
                        // invalid_client. Any other error (e.g. invalid_grant for a revoked refresh token)
                        // means the client authenticated, and the text would mislead.
                        var needsErrorDescription = hasErrorDescription
                            && root.TryGetProperty("error", out var error)
                            && error.ValueKind == JsonValueKind.String
                            && error.GetString() == "invalid_client"
                            && !root.TryGetProperty("error_description", out _);
                        var needsExtensions = hasErrorExtensions
                            && !root.TryGetProperty("extensions", out _);

                        if (needsErrorDescription || needsExtensions)
                        {
                            using var ms = new MemoryStream();
                            using (var writer = new Utf8JsonWriter(ms))
                            {
                                writer.WriteStartObject();

                                foreach (var property in root.EnumerateObject())
                                {
                                    property.WriteTo(writer);
                                }

                                if (needsErrorDescription)
                                {
                                    writer.WriteString("error_description", (string)errorDescObj!);
                                    _logger.LogDebug("Injected error_description into token error response");
                                }

                                if (needsExtensions)
                                {
                                    var extensions = (Dictionary<string, object>)errorExtObj!;
                                    writer.WritePropertyName("extensions");
                                    JsonSerializer.Serialize(writer, extensions);
                                    _logger.LogDebug("Injected extensions into token error response");
                                }

                                writer.WriteEndObject();
                            }

                            responseBody = System.Text.Encoding.UTF8.GetString(ms.ToArray());
                        }
                    }
                }
                catch (JsonException ex)
                {
                    _logger.LogDebug(ex, "Could not parse token response body for error injection");
                }
            }
        }

        context.Response.Body = originalBody;
        context.Response.Headers.Remove("Content-Length");
        await context.Response.WriteAsync(responseBody);
    }
}
