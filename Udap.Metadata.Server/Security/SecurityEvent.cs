#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Metadata.Server.Security;

/// <summary>
/// Structured security event logged by <see cref="SecurityEventMiddleware"/>.
/// </summary>
public record SecurityEvent
{
    public SecurityEventType EventType { get; init; }
    public string? Login { get; init; }

    /// <summary>
    /// <c>true</c> when <see cref="Login"/> comes from the authenticated user. <c>false</c> when authentication
    /// failed and <see cref="Login"/> was read from a token that was not validated, so it is only what the caller claimed.
    /// </summary>
    public bool LoginVerified { get; init; }

    public string? AuthType { get; init; }
    public string? SrcIp { get; init; }
    public int HttpResponse { get; init; }
    public string? Method { get; init; }
    public string? Path { get; init; }
    /// <summary>
    /// The names of the request's query parameters, comma separated, e.g. <c>name,birthdate</c>. Values are not
    /// recorded: FHIR search values are often patient details.
    /// </summary>
    public string? Query { get; init; }
    public string? AcceptEncoding { get; init; }
    public string? ContentEncoding { get; init; }
}
