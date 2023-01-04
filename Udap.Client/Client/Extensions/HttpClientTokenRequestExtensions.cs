#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using IdentityModel;
using IdentityModel.Client;
using Udap.Client.Client.Messages;
using Udap.Client.Internal;
using Udap.Common;

namespace Udap.Client.Client.Extensions;

/// <summary>
/// HttpClient extensions for UDAP extended OAuth token requests
/// </summary>
public static class HttpClientTokenRequestExtensions
{
    /// <summary>
    /// Sends a token request using the client_credentials grant type.
    /// </summary>
    /// <param name="client">The client.</param>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns></returns>
    public static async Task<TokenResponse> RequestClientCredentialsTokenAsync(
        this HttpMessageInvoker client,
        UdapClientCredentialsTokenRequest request, 
        CancellationToken cancellationToken = default)
    {
        var clone = request.Clone();

        clone.Parameters.AddRequired(OidcConstants.TokenRequest.GrantType, OidcConstants.GrantTypes.ClientCredentials);
        clone.Parameters.AddOptional(OidcConstants.TokenRequest.Scope, request.Scope);
        clone.Parameters.AddRequired(UdapConstants.TokenRequest.Udap, UdapConstants.UdapVersionsSupportedValue);

        return await client.RequestTokenAsync(clone, cancellationToken).ConfigureAwait();
    }

    internal static async Task<TokenResponse> RequestTokenAsync(this HttpMessageInvoker client, ProtocolRequest request, CancellationToken cancellationToken = default)
    {
        request.Prepare();
        request.Method = HttpMethod.Post;

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, cancellationToken).ConfigureAwait();
        }
        catch (Exception ex)
        {
            return ProtocolResponse.FromException<TokenResponse>(ex);
        }

        return await ProtocolResponse.FromHttpResponseAsync<TokenResponse>(response).ConfigureAwait();
    }
}
