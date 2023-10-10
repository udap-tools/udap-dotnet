#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using IdentityModel.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Configuration;
using Udap.Common.Extensions;
using Udap.Model;

namespace Udap.Client.Client;

public class HeaderAugmentationHandler : DelegatingHandler
{
    private readonly UdapClientOptions _udapClientOptions;

    public HeaderAugmentationHandler(IOptionsMonitor<UdapClientOptions> udapClientOptions)
    {
        _udapClientOptions = udapClientOptions.CurrentValue;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (_udapClientOptions.Headers != null)
        {
            foreach (var pair in _udapClientOptions.Headers)
            {
                request.Headers.Add(pair.Key, pair.Value);
            }
        }

        return await base.SendAsync(request, cancellationToken);
    }
}

public class UdapClientMessageHandler : DelegatingHandler, IUdapClientEvents
{
    private readonly UdapClientDiscoveryValidator _clientDiscoveryValidator;
    private readonly ILogger<UdapClient> _logger;


    public UdapClientMessageHandler(
        UdapClientDiscoveryValidator clientDiscoveryValidator,
        ILogger<UdapClient> logger)
    {
        _clientDiscoveryValidator = clientDiscoveryValidator;
        _logger = logger;
    }

    public UdapMetadata? UdapDynamicClientRegistrationDocument { get; set; }


    /// <inheritdoc/>
    public event Action<X509Certificate2>? Untrusted
    {
        add => _clientDiscoveryValidator.Untrusted += value;
        remove => _clientDiscoveryValidator.Untrusted -= value;
    }

    /// <inheritdoc/>
    public event Action<X509ChainElement>? Problem
    {
        add => _clientDiscoveryValidator.Problem += value;
        remove => _clientDiscoveryValidator.Problem -= value;
    }

    /// <inheritdoc/>
    public event Action<X509Certificate2, Exception>? Error
    {
        add => _clientDiscoveryValidator.Error += value;
        remove => _clientDiscoveryValidator.Error -= value;
    }

    /// <inheritdoc/>
    public event Action<string>? TokenError;


    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var baseUrl = request.RequestUri?.AbsoluteUri.GetBaseUrlFromMetadataUrl();
        var community = request.RequestUri?.Query.GetCommunityFromQueryParams();


        var metadata = await base.SendAsync(request, cancellationToken);
        metadata.EnsureSuccessStatusCode();

        var disco = await metadata.Content.ReadFromJsonAsync<DiscoveryDocumentResponse>(cancellationToken: cancellationToken);

        if (disco == null)
        {
            throw new SecurityTokenInvalidTypeException("Failed to read UDAP Discovery Document");
        }

        if (disco.HttpStatusCode == HttpStatusCode.OK && !disco.IsError)
        {
            _clientDiscoveryValidator.UdapServerMetaData = disco.Json.Deserialize<UdapMetadata>();
            _logger.LogDebug(_clientDiscoveryValidator.UdapServerMetaData?.SerializeToJson());

            if (!await _clientDiscoveryValidator.ValidateJwtToken(_clientDiscoveryValidator.UdapServerMetaData!, baseUrl!))
            {
                throw new SecurityTokenInvalidTypeException("Failed JWT Token Validation");
            }

            if (!await _clientDiscoveryValidator.ValidateTrustChain(community))
            {
                throw new UnauthorizedAccessException("Failed Trust Chain Validation");
            }
        }
        else
        {
            NotifyTokenError(disco.Error ?? "Unknown Error");
        }

        return metadata;

    }

    private void NotifyTokenError(string message)
    {
        _logger.LogWarning(message);

        if (TokenError != null)
        {
            try
            {
                TokenError(message);
            }
            catch
            {
                // ignored
            }
        }
    }
}