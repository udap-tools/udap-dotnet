#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Client;
using Udap.Model;

namespace Udap.Common.Tests.Client;

public class DiscoveryPolicyTests
{
    [Fact]
    public void DefaultValues_AreCorrect()
    {
        var policy = new DiscoveryPolicy();

        Assert.Equal(string.Empty, policy.Authority);
        Assert.Equal(UdapConstants.Discovery.DiscoveryEndpoint, policy.DiscoveryDocumentPath);
        Assert.True(policy.RequireHttps);
        Assert.True(policy.AllowHttpOnLoopback);
        Assert.True(policy.ValidateEndpoints);
        Assert.True(policy.RequireKeySet);
        Assert.Empty(policy.EndpointValidationExcludeList);
        Assert.Empty(policy.AdditionalEndpointBaseAddresses);
    }

    [Fact]
    public void DefaultMetadataServerPolicy_ValidateEndpoints_IsFalse()
    {
        var policy = DiscoveryPolicy.DefaultMetadataServerPolicy();

        Assert.False(policy.ValidateEndpoints);
    }

    [Fact]
    public void LoopbackAddresses_ContainsLocalhostAnd127()
    {
        var policy = new DiscoveryPolicy();

        Assert.Contains("localhost", policy.LoopbackAddresses);
        Assert.Contains("127.0.0.1", policy.LoopbackAddresses);
    }

    [Fact]
    public void AuthorityValidationStrategy_HasDefault()
    {
        var policy = new DiscoveryPolicy();

        Assert.NotNull(policy.AuthorityValidationStrategy);
    }
}
