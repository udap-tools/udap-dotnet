// UdapModel is modeled after IdentityModel. See https://github.com/IdentityModel/IdentityModel
// 
// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using IdentityModel.Client;
using Udap.Client.Client.Messages;
using Udap.Common.Extensions;

namespace Udap.Client.Client.Extensions
{
    /// <summary>
    /// HttpClient extensions for UDAP discovery
    /// </summary>
    public static class HttpUdapClientDiscoveryExtensions
    {
        /// <summary>
        /// Sends a UDAP discovery document request
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="address">The address.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<UdapDiscoveryDocumentResponse> GetUdapDiscoveryDocument(
            this HttpClient client,
            string? address = null, 
            CancellationToken cancellationToken = default)
        {
            return await client
                .GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest { Address = address },
                    cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Sends a discovery document request
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<UdapDiscoveryDocumentResponse> GetUdapDiscoveryDocument(
            this HttpMessageInvoker client, 
            UdapDiscoveryDocumentRequest request,
            CancellationToken cancellationToken = default)
        {
            string address;
            if (request.Address.IsPresent())
            {
                address = request.Address;
            }
            else if (client is HttpClient httpClient && httpClient.BaseAddress != null)
            {
                address = httpClient.BaseAddress.AbsoluteUri;
            }
            else
            {
                throw new ArgumentException("An address is required.");
            }

            var parsed = DiscoveryEndpoint.ParseUrl(address, request.Policy.DiscoveryDocumentPath, request.Community);
            var authority = parsed.Authority;
            var url = parsed.Url;

            if (request.Policy.Authority.IsMissing())
            {
                request.Policy.Authority = authority;
            }

            var jwkUrl = "";

            if (!DiscoveryEndpoint.IsSecureScheme(new Uri(url), request.Policy))
            {
                return ProtocolResponse.FromException<UdapDiscoveryDocumentResponse>(
                    new InvalidOperationException("HTTPS required"), $"Error connecting to {url}. HTTPS required.");
            }

            try
            {
                var clone = request.Clone();

                clone.Method = HttpMethod.Get;
                clone.Prepare();

                clone.RequestUri = new Uri(url);

                var response = await client.SendAsync(clone, cancellationToken).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    return await ProtocolResponse
                        .FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(response,
                            $"Error connecting to {url}: {response.ReasonPhrase}").ConfigureAwait(false);
                }

                var joe = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                var disco = await ProtocolResponse
                    .FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(response, request.Policy)
                    .ConfigureAwait(false);

                if (disco.IsError)
                {
                    return disco;
                }

                try
                {
                    jwkUrl = disco.JwksUri;
                    if (jwkUrl != null)
                    {
                        var jwkClone = request.Clone<JsonWebKeySetRequest>();
                        jwkClone.Method = HttpMethod.Get;
                        jwkClone.Address = jwkUrl;
                        jwkClone.Prepare();

                        var jwkResponse = await client.GetJsonWebKeySetAsync(jwkClone, cancellationToken)
                            .ConfigureAwait(false);

                        if (jwkResponse.IsError)
                        {
                            return await ProtocolResponse
                                .FromHttpResponseAsync<UdapDiscoveryDocumentResponse>(jwkResponse.HttpResponse,
                                    $"Error connecting to {jwkUrl}: {jwkResponse.HttpErrorReason}").ConfigureAwait(false);
                        }

                        disco.KeySet = jwkResponse.KeySet;
                    }

                    return disco;
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    return ProtocolResponse.FromException<UdapDiscoveryDocumentResponse>(ex,
                        $"Error connecting to {jwkUrl}. {ex.Message}.");
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                return ProtocolResponse.FromException<UdapDiscoveryDocumentResponse>(ex,
                    $"Error connecting to {url}. {ex.Message}.");
            }
        }
    }
}