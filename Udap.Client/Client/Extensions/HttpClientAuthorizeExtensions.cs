#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text;
using Udap.Client.Messages;

namespace Udap.Client.Extensions;

/// <summary>
/// HttpClient extensions for sending OAuth 2.0 authorization requests.
/// </summary>
public static class HttpClientAuthorizeExtensions
{
    /// <summary>
    /// Sends a fully constructed authorization request URL to the authorization endpoint using the
    /// requested HTTP method.  For <see cref="AuthorizeHttpMethod.Post"/> the query string is sent as
    /// an application/x-www-form-urlencoded body instead, so GET and POST carry identical parameter
    /// encodings.  Per SSRAA (see <a href="https://jira.hl7.org/browse/FHIR-52960">FHIR-52960</a>)
    /// Authorization Servers SHALL support both methods for the authorization code flow.
    /// </summary>
    /// <param name="client">The client.</param>
    /// <param name="authorizeUrl">The complete authorization request URL, including query string parameters.</param>
    /// <param name="method">The HTTP method to use.  Defaults to <see cref="AuthorizeHttpMethod.Get"/>.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The HTTP response from the authorization endpoint.</returns>
    public static Task<HttpResponseMessage> AuthorizeAsync(
        this HttpClient client,
        string authorizeUrl,
        AuthorizeHttpMethod method = AuthorizeHttpMethod.Get,
        CancellationToken cancellationToken = default)
    {
        if (method == AuthorizeHttpMethod.Post)
        {
            var queryIndex = authorizeUrl.IndexOf('?');
            var endpoint = queryIndex >= 0 ? authorizeUrl[..queryIndex] : authorizeUrl;
            var formData = queryIndex >= 0 ? authorizeUrl[(queryIndex + 1)..] : string.Empty;

            var content = new StringContent(formData, Encoding.UTF8, "application/x-www-form-urlencoded");

            return client.PostAsync(endpoint, content, cancellationToken);
        }

        return client.GetAsync(authorizeUrl, cancellationToken);
    }
}
