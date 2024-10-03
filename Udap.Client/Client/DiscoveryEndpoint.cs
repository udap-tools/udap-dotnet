// UdapModel is modeled after IdentityModel. See https://github.com/IdentityModel/IdentityModel
// 
// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Udap.Common.Extensions;
using Udap.Model;

namespace Udap.Client.Client;

/// <summary>
/// Represents a URL to a discovery endpoint - parsed to separate the URL and authority
/// </summary>
public class DiscoveryEndpoint
{
    /// <summary>
    /// Parses a URL and turns it into authority and discovery endpoint URL.
    /// </summary>
    /// <param name="input">The input.</param>
    /// <param name="path">The path to the discovery document. If not specified this defaults to .well-known/udap</param>
    /// <param name="community">Optional community qualifier</param>
    /// <returns></returns>
    /// <exception cref="System.InvalidOperationException">
    /// Malformed URL
    /// </exception>
    public static DiscoveryEndpoint ParseUrl(string input, string? path = null, string? community = null)
    {
        if (input.Contains(UdapConstants.Discovery.DiscoveryEndpoint))
        {
            var i = input.IndexOf(UdapConstants.Discovery.DiscoveryEndpoint, StringComparison.Ordinal);
            return new DiscoveryEndpoint(input.Substring(0, i).RemoveTrailingSlash(), input);
        }

        if (string.IsNullOrEmpty(path))
        {
            path = UdapConstants.Discovery.DiscoveryEndpoint;
        }

        if (!string.IsNullOrEmpty(community))
        {
            path = path.RemoveTrailingSlash() + "?community=" + community;
        }

        var success = Uri.TryCreate(input, UriKind.Absolute, out var uri);
        if (success == false)
        {
            throw new InvalidOperationException("Malformed URL");
        }

        if (!IsValidScheme(uri))
        {
            throw new InvalidOperationException("Malformed URL");
        }

        var url = input.RemoveTrailingSlash();
        if (path.StartsWith("/"))
        {
            path = path.Substring(1);
        }

        if (url.EndsWith(path, StringComparison.OrdinalIgnoreCase))
        {
            return new DiscoveryEndpoint(url.Substring(0, url.Length - path.Length - 1), url);
        }
        else
        {
            return new DiscoveryEndpoint(url, url.EnsureTrailingSlash() + path);
        }
    }

    /// <summary>
    /// Determines whether the URL uses http or https.
    /// </summary>
    /// <param name="url">The URL.</param>
    /// <returns>
    ///   <c>true</c> if [is valid scheme] [the specified URL]; otherwise, <c>false</c>.
    /// </returns>
    public static bool IsValidScheme(Uri? url)
    {
        if (url == null)
        {
            return false;
        }

        if (string.Equals(url.Scheme, "http", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(url.Scheme, "https", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// Determines whether it uses a secure scheme according to the policy.
    /// </summary>
    /// <param name="url">The URL.</param>
    /// <param name="policy">The policy.</param>
    /// <returns>
    ///   <c>true</c> if [is secure scheme] [the specified URL]; otherwise, <c>false</c>.
    /// </returns>
    public static bool IsSecureScheme(Uri url, DiscoveryPolicy policy)
    {
        if (policy.RequireHttps)
        {
            if (policy.AllowHttpOnLoopback)
            {
                var hostName = url.DnsSafeHost;

                foreach (var address in policy.LoopbackAddresses)
                {
                    if (string.Equals(hostName, address, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }

            return string.Equals(url.Scheme, "https", StringComparison.OrdinalIgnoreCase);
        }

        return true;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DiscoveryEndpoint"/> class.
    /// </summary>
    /// <param name="authority">The authority.</param>
    /// <param name="url">The discovery endpoint URL.</param>
    public DiscoveryEndpoint(string authority, string url)
    {
        Authority = authority;
        Url = url;
    }
    /// <summary>
    /// Gets or sets the authority.
    /// </summary>
    /// <value>
    /// The authority.
    /// </value>
    public string Authority { get; }

    /// <summary>
    /// Gets or sets the discovery endpoint.
    /// </summary>
    /// <value>
    /// The discovery endpoint.
    /// </value>
    public string Url { get; }
}