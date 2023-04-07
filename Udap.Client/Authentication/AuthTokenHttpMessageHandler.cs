#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Http.Headers;

namespace Udap.Client.Authentication;
public class AuthTokenHttpMessageHandler : DelegatingHandler
{
    private readonly IAccessTokenProvider _accessTokenProvider;

    public AuthTokenHttpMessageHandler(IAccessTokenProvider accessTokenProvider)
    {
        _accessTokenProvider = accessTokenProvider;
    }

    /// <summary>Sends an HTTP request to the inner handler to send to the server as an asynchronous operation.</summary>
    /// <param name="request">The HTTP request message to send to the server.</param>
    /// <param name="cancellationToken">A cancellation token to cancel operation.</param>
    /// <exception cref="T:System.ArgumentNullException">The <paramref name="request" /> was <see langword="null" />.</exception>
    /// <returns>The task object representing the asynchronous operation.</returns>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await _accessTokenProvider.GetAccessToken(cancellationToken);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        return await base.SendAsync(request, cancellationToken);
    }
}