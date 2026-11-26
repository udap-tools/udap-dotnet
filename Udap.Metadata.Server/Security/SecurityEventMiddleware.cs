#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Udap.Metadata.Server.Security;

/// <summary>
/// Middleware that logs structured security events for both successful and failed authentication.
/// Place this after <c>UseAuthentication()</c> and before <c>UseAuthorization()</c>.
/// Logs a single <see cref="SecurityEvent"/> per request after the response completes.
/// </summary>
public class SecurityEventMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SecurityEventMiddleware> _logger;

    public SecurityEventMiddleware(RequestDelegate next, ILogger<SecurityEventMiddleware> logger)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var isAuthenticated = context.User.Identity is { IsAuthenticated: true };

        await _next(context);

        var securityEvent = BuildSecurityEvent(context, isAuthenticated);
        LogSecurityEvent(securityEvent);
    }

    internal SecurityEvent BuildSecurityEvent(HttpContext context, bool isAuthenticated)
    {
        var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
        var authType = ExtractAuthScheme(authHeader);

        string? login;

        if (isAuthenticated)
        {
            login = ResolveLoginFromPrincipal(context);
        }
        else
        {
            login = ResolveLoginFromHeader(context);
        }

        // Every value below except SrcIp and HttpResponse comes from the request, so control characters are removed
        // and lengths capped before they reach a log line.
        return new SecurityEvent
        {
            EventType = isAuthenticated ? SecurityEventType.SuccessfulAccess : SecurityEventType.AuthenticationFailure,
            Login = Sanitize(login),
            LoginVerified = isAuthenticated && login != null,
            AuthType = Sanitize(authType),
            SrcIp = context.Connection.RemoteIpAddress?.ToString(),
            HttpResponse = context.Response.StatusCode,
            Method = Sanitize(context.Request.Method),
            Path = Sanitize(context.Request.Path.Value, MaxPathLength),
            Query = QueryParameterNames(context.Request),
            AcceptEncoding = Sanitize(context.Request.Headers.AcceptEncoding.FirstOrDefault()),
            ContentEncoding = Sanitize(context.Response.Headers.ContentEncoding.FirstOrDefault())
        };
    }

    private const int MaxFieldLength = 256;
    private const int MaxPathLength = 1024;

    /// <summary>
    /// The query parameter names, comma separated, without their values.
    /// </summary>
    internal static string? QueryParameterNames(HttpRequest request)
    {
        if (!request.QueryString.HasValue || request.Query.Count == 0)
        {
            return null;
        }

        return Sanitize(string.Join(",", request.Query.Keys), MaxPathLength);
    }

    /// <summary>
    /// Removes control characters (including CR and LF, which could forge extra log lines) and caps the length.
    /// </summary>
    internal static string? Sanitize(string? value, int maxLength = MaxFieldLength)
    {
        if (value == null)
        {
            return null;
        }

        if (value.Length == 0)
        {
            return string.Empty;
        }

        // Line breaks first, in the form log-forging analyzers recognize, then any other control characters.
        var cleaned = value.Replace("\r", string.Empty).Replace("\n", string.Empty);
        if (cleaned.Any(char.IsControl))
        {
            cleaned = new string(cleaned.Where(c => !char.IsControl(c)).ToArray());
        }

        return cleaned.Length > maxLength ? cleaned[..maxLength] + "..." : cleaned;
    }

    internal void LogSecurityEvent(SecurityEvent securityEvent)
    {
        if (securityEvent.EventType == SecurityEventType.SuccessfulAccess)
        {
            _logger.LogInformation(
                "SecurityEvent={EventType}, Login={Login}, LoginVerified={LoginVerified}, AuthType={AuthType}, SrcIp={SrcIp}, " +
                "HttpResponse={HttpResponse}, Method={Method}, Path={Path}, Query={Query}, " +
                "AcceptEncoding={AcceptEncoding}, ContentEncoding={ContentEncoding}",
                securityEvent.EventType,
                securityEvent.Login,
                securityEvent.LoginVerified,
                securityEvent.AuthType,
                securityEvent.SrcIp,
                securityEvent.HttpResponse,
                securityEvent.Method,
                securityEvent.Path,
                securityEvent.Query,
                securityEvent.AcceptEncoding,
                securityEvent.ContentEncoding);
        }
        else
        {
            _logger.LogWarning(
                "SecurityEvent={EventType}, Login={Login}, LoginVerified={LoginVerified}, AuthType={AuthType}, SrcIp={SrcIp}, " +
                "HttpResponse={HttpResponse}, Method={Method}, Path={Path}, Query={Query}, " +
                "AcceptEncoding={AcceptEncoding}, ContentEncoding={ContentEncoding}",
                securityEvent.EventType,
                securityEvent.Login,
                securityEvent.LoginVerified,
                securityEvent.AuthType,
                securityEvent.SrcIp,
                securityEvent.HttpResponse,
                securityEvent.Method,
                securityEvent.Path,
                securityEvent.Query,
                securityEvent.AcceptEncoding,
                securityEvent.ContentEncoding);
        }
    }

    /// <summary>
    /// Resolves the login identity from the authenticated <see cref="System.Security.Claims.ClaimsPrincipal"/>.
    /// Prefers client_id, falls back to sub claim.
    /// </summary>
    internal static string? ResolveLoginFromPrincipal(HttpContext context)
    {
        var principal = context.User;
        return principal.FindFirst("client_id")?.Value
               ?? principal.FindFirst("sub")?.Value;
    }

    /// <summary>
    /// Attempts to resolve the login identity from the Authorization header JWT
    /// when authentication has failed.
    /// </summary>
    internal string? ResolveLoginFromHeader(HttpContext context)
    {
        var authHeader = context.Request.Headers.Authorization.FirstOrDefault();

        if (string.IsNullOrWhiteSpace(authHeader))
        {
            _logger.LogDebug("Cannot resolve login: no Authorization header");
            return null;
        }

        _logger.LogDebug("Authorization header length: {Length}", authHeader.Length);

        var tokenValue = ExtractTokenValue(authHeader);

        if (!string.IsNullOrWhiteSpace(tokenValue))
        {
            return ExtractClientId(tokenValue, _logger);
        }

        // The JWT bearer handler may have consumed the token from the header.
        // Try the authentication result for failure details.
        var authResult = context.Features.Get<Microsoft.AspNetCore.Authentication.IAuthenticateResultFeature>();
        if (authResult?.AuthenticateResult?.Failure != null)
        {
            _logger.LogDebug("Auth failure reason: {Reason}", authResult.AuthenticateResult.Failure.Message);
        }

        _logger.LogDebug("Cannot resolve login: no token value after scheme (header={Header})",
            authHeader.Length > 20 ? authHeader[..20] + "..." : authHeader);

        return null;
    }

    /// <summary>
    /// Extracts the authentication scheme (Bearer, DPoP, etc.) from the Authorization header.
    /// </summary>
    public static string? ExtractAuthScheme(string? authorizationHeader)
    {
        if (string.IsNullOrWhiteSpace(authorizationHeader))
        {
            return null;
        }

        var spaceIndex = authorizationHeader.IndexOf(' ');
        return spaceIndex > 0 ? authorizationHeader[..spaceIndex] : authorizationHeader;
    }

    /// <summary>
    /// Extracts the token value from the Authorization header, stripping the scheme prefix.
    /// Handles any scheme (Bearer, DPoP, etc.) with any amount of whitespace.
    /// </summary>
    public static string? ExtractTokenValue(string authorizationHeader)
    {
        var parts = authorizationHeader.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length > 1 ? parts[1].Trim() : null;
    }

    /// <summary>
    /// Attempts to parse the JWT and extract the client_id claim.
    /// Returns null if the token cannot be parsed or has no client_id claim.
    /// </summary>
    public static string? ExtractClientId(string tokenValue, ILogger? logger = null)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();

            if (!handler.CanReadToken(tokenValue))
            {
                logger?.LogDebug("Cannot resolve login: token is not a readable JWT");
                return null;
            }

            var jwt = handler.ReadJwtToken(tokenValue);
            var clientId = jwt.Claims.FirstOrDefault(c => c.Type == "client_id")?.Value;

            if (clientId != null)
            {
                return clientId;
            }

            logger?.LogDebug(
                "Cannot resolve login: JWT has no client_id claim. Available claims: {ClaimTypes}",
                string.Join(", ", jwt.Claims.Select(c => c.Type).Distinct()));

            return null;
        }
        catch (Exception ex)
        {
            logger?.LogDebug(ex, "Cannot resolve login: failed to parse JWT");
            return null;
        }
    }
}
