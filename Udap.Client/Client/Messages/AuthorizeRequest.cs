#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Client.Messages;

/// <summary>
/// Encapsulates parameters for an OAuth 2.0 authorization request.
/// </summary>
public class AuthorizeRequest
{
    /// <summary>
    /// The authorization endpoint URL.
    /// </summary>
    public required string AuthorizationUrl { get; init; }

    /// <summary>
    /// The client identifier.
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The response type (e.g., "code").
    /// </summary>
    public string? ResponseType { get; init; }

    /// <summary>
    /// The requested scope.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// The redirect URI.
    /// </summary>
    public string? RedirectUri { get; init; }

    /// <summary>
    /// The state parameter for CSRF protection.
    /// </summary>
    public string? State { get; init; }

    /// <summary>
    /// The nonce for replay protection.
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// A hint about the login identifier the user might use.
    /// </summary>
    public string? LoginHint { get; init; }

    /// <summary>
    /// Requested authentication context class reference values.
    /// </summary>
    public string? AcrValues { get; init; }

    /// <summary>
    /// Whether to prompt the user for reauthentication or consent.
    /// </summary>
    public string? Prompt { get; init; }

    /// <summary>
    /// The response mode (e.g., "query", "fragment", "form_post").
    /// </summary>
    public string? ResponseMode { get; init; }

    /// <summary>
    /// The PKCE code challenge.
    /// </summary>
    public string? CodeChallenge { get; init; }

    /// <summary>
    /// The PKCE code challenge method (e.g., "S256").
    /// </summary>
    public string? CodeChallengeMethod { get; init; }

    /// <summary>
    /// The display mode for the authorization page.
    /// </summary>
    public string? Display { get; init; }

    /// <summary>
    /// Maximum authentication age in seconds.
    /// </summary>
    public int? MaxAge { get; init; }

    /// <summary>
    /// Preferred locales for the user interface.
    /// </summary>
    public string? UiLocales { get; init; }

    /// <summary>
    /// A previously issued ID token as a hint.
    /// </summary>
    public string? IdTokenHint { get; init; }

    /// <summary>
    /// A pushed authorization request URI.
    /// </summary>
    public string? RequestUri { get; init; }

    /// <summary>
    /// Additional parameters to include in the request.
    /// </summary>
    public object? Extra { get; init; }
}
