#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Duende.IdentityModel.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Configuration;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Model;

namespace Udap.Client;

/// <summary>
/// An HTTP message handler that injects custom headers from <see cref="UdapClientOptions"/> into every outgoing request.
/// </summary>
public class HeaderAugmentationHandler : DelegatingHandler
{
    private readonly UdapClientOptions _udapClientOptions;

    public HeaderAugmentationHandler(IOptionsMonitor<UdapClientOptions> udapClientOptions)
    {
        _udapClientOptions = udapClientOptions.CurrentValue;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (_udapClientOptions.Headers != null)
        {
            foreach (var pair in _udapClientOptions.Headers)
            {
                request.Headers.Add(pair.Key, pair.Value);
            }
        }

        return base.SendAsync(request, cancellationToken);
    }
}

/// <summary>
/// An HTTP message handler that performs UDAP metadata discovery validation (JWT + trust chain) on responses
/// before they reach the caller, used internally by <see cref="UdapClient"/>.
/// </summary>
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

    /// <summary>
    /// Gets or sets the validated UDAP server metadata obtained during discovery.
    /// </summary>
    public UdapMetadata? UdapDynamicClientRegistrationDocument { get; set; }


    /// <inheritdoc/>
    public event Action<X509Certificate2>? Untrusted
    {
        add => _clientDiscoveryValidator.Untrusted += value;
        remove => _clientDiscoveryValidator.Untrusted -= value;
    }

    /// <inheritdoc/>
    public event Action<ChainElementInfo>? Problem
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

        var disco = await ProtocolResponse.FromHttpResponseAsync<ProtocolResponse>(metadata);

        if (disco.HttpStatusCode == HttpStatusCode.OK && !disco.IsError)
        {
            _clientDiscoveryValidator.UdapServerMetadata = disco.Json?.Deserialize<UdapMetadata>();
            _logger.LogDebug("UdapServerMetadata: {UdapServerMetadataJson}", _clientDiscoveryValidator.UdapServerMetadata?.SerializeToJson());

            if (!await _clientDiscoveryValidator.ValidateJwtToken(_clientDiscoveryValidator.UdapServerMetadata!, baseUrl!))
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
        _logger.LogWarning("Token error occurred: {ErrorMessage}", message);

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