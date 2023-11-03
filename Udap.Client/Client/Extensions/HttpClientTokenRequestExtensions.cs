#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

//
// Modification from IdentityModel.Client.HttpClientTokenRequestExtensions for UDAP profiles parameter validation differences
//
// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.
//


using System.Text;
using System.Text.Json;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Udap.Model;
using Udap.Model.Access;
using TokenResponse = IdentityModel.Client.TokenResponse;

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
    public static async Task<TokenResponse> UdapRequestClientCredentialsTokenAsync(
        this HttpMessageInvoker client,
        UdapClientCredentialsTokenRequest request, 
        CancellationToken cancellationToken = default)
    {
        var clone = request.Clone();

        clone.Parameters.AddRequired(OidcConstants.TokenRequest.GrantType, OidcConstants.GrantTypes.ClientCredentials);
        clone.Parameters.AddOptional(OidcConstants.TokenRequest.Scope, request.Scope);
        clone.Parameters.AddRequired(UdapConstants.TokenRequest.Udap, UdapConstants.UdapVersionsSupportedValue);

        return await client.RequestTokenAsync(clone, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a token request using the authorization_code grant type.
    /// </summary>
    /// <param name="client">The client.</param>
    /// <param name="tokenRequest">The request.</param>
    /// <param name="token">The cancellation token.</param>
    /// <returns></returns>
    public static async Task<TokenResponse> ExchangeCodeForTokenResponse(
        this HttpMessageInvoker client, 
        AuthorizationCodeTokenRequest tokenRequest,
        CancellationToken token = default)
    {
        var clone = tokenRequest.Clone();

        clone.Parameters.AddRequired(OidcConstants.TokenRequest.GrantType, OidcConstants.GrantTypes.AuthorizationCode);
        clone.Parameters.AddRequired(OidcConstants.TokenRequest.Code, tokenRequest.Code);
        // TODO: revisit:: This is not required according to https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
        // UDAP profiles also do not require it.  
        // I think that the Duende.IdentityServer.Validation.TokenRequestValidator will always fail without it.
        // The https://www.udap.org/UDAPTestTool/ sends the redirect_uri.  So not sure on the path forward yet.
        clone.Parameters.AddOptional(OidcConstants.TokenRequest.RedirectUri, tokenRequest.RedirectUri);
        clone.Parameters.AddRequired(UdapConstants.TokenRequest.Udap, UdapConstants.UdapVersionsSupportedValue);

        foreach (var resource in tokenRequest.Resource)
        {
            clone.Parameters.AddRequired(OidcConstants.TokenRequest.Resource, resource, allowDuplicates: true);
        }

        return await client.RequestTokenAsync(clone, token).ConfigureAwait(false);
    }

    internal static async Task<TokenResponse> RequestTokenAsync(this HttpMessageInvoker client, ProtocolRequest request, CancellationToken cancellationToken = default)
    {
        request.Prepare();
        request.Method = HttpMethod.Post;

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return ProtocolResponse.FromException<TokenResponse>(ex);
        }

        return await ProtocolResponse.FromHttpResponseAsync<TokenResponse>(response).ConfigureAwait(false);
    }


    /// <summary>
    /// Sends a token request using the authorization_code grant type.  Typically used when called from
    /// from a OAuthHandler implementation.  TieredOAuthAuthenticationHandler is an implementation that
    /// calls this method.
    /// </summary>
    /// <param name="client">The client.</param>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><see cref="OAuthTokenResponse"/></returns>
    public static async Task<OAuthTokenResponse> ExchangeCodeForAuthTokenResponse(
        this HttpMessageInvoker client, 
        AuthorizationCodeTokenRequest request, 
        CancellationToken cancellationToken = default)
    {
        var clone = request.Clone();

        clone.Parameters.AddRequired(OidcConstants.TokenRequest.GrantType, OidcConstants.GrantTypes.AuthorizationCode);
        clone.Parameters.AddRequired(OidcConstants.TokenRequest.Code, request.Code);
        // TODO: revisit:: This is not required according to https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
        // UDAP profiles also do not require it.  
        // I think that the Duende.IdentityServer.Validation.TokenRequestValidator will always fail without it.
        // The https://www.udap.org/UDAPTestTool/ sends the redirect_uri.  So not sure on the path forward yet.
        clone.Parameters.AddOptional(OidcConstants.TokenRequest.RedirectUri, request.RedirectUri);
        clone.Parameters.AddRequired(UdapConstants.TokenRequest.Udap, UdapConstants.UdapVersionsSupportedValue);

        foreach (var resource in request.Resource)
        {
            clone.Parameters.AddRequired(OidcConstants.TokenRequest.Resource, resource, allowDuplicates: true);
        }

        clone.Prepare();
        clone.Method = HttpMethod.Post;

        var response = await client.SendAsync(clone, cancellationToken);

        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        return response.IsSuccessStatusCode switch
        {
            true => OAuthTokenResponse.Success(JsonDocument.Parse(body)),
            false => PrepareFailedOAuthTokenResponse(JsonDocument.Parse(body))
        };
    }

    //TODO: how can I refactor out the OAuthTokenResponse?  It requires the Microsoft.AspNetCore.App framework to be included.
    // I need a Udap.TieredOauth package so simple clients do not need this reference.
    private static OAuthTokenResponse PrepareFailedOAuthTokenResponse(JsonDocument jsonDocument)
    {
        var root = jsonDocument.RootElement;
        var error = root.GetString("error");

        var result = new StringBuilder("OAuth token endpoint failure: ");
        result.Append(error);

        if (root.TryGetProperty("error_description", out var errorDescription))
        {
            result.Append(";Description=");
            result.Append(errorDescription);
        }

        if (root.TryGetProperty("error_uri", out var errorUri))
        {
            result.Append(";Uri=");
            result.Append(errorUri);
        }

        var exception = new Exception(result.ToString());
        exception.Data["error"] = error.ToString();
        exception.Data["error_description"] = errorDescription.ToString();
        exception.Data["error_uri"] = errorUri.ToString();

        return OAuthTokenResponse.Failed(exception);
    }
}
