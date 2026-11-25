#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Web;
using Duende.IdentityModel.Client;
using Duende.IdentityServer.Services;
using NSubstitute;
using Udap.Client;
using Udap.Server.Security.Authentication.TieredOAuth;
using Xunit;

namespace UdapServer.Tests.Conformance.Tiered;

/// <summary>
/// The idp parameter comes from an anonymous authorize request, and the server sends requests to it.
/// </summary>
public class TieredOAuthIdPRequestTests
{
    [Theory]
    [InlineData("https://idp.example.com")]
    [InlineData("https://idp.example.com:8443/tenant?community=udap://community1")]
    [InlineData("http://localhost:5055")]
    [InlineData("http://127.0.0.1:5055")]
    public void ValidateIdPUri_AcceptsHttpsAndLoopbackHttp(string idp)
    {
        Assert.NotNull(TieredOAuthHelpers.ValidateIdPUri(idp));
    }

    [Theory]
    [InlineData("http://idp.example.com")]
    [InlineData("http://169.254.169.254/latest/meta-data")]
    [InlineData("https://user:secret@idp.example.com")]
    [InlineData("file:///etc/passwd")]
    [InlineData("/relative")]
    [InlineData("not a url")]
    public void ValidateIdPUri_RefusesEverythingElse(string idp)
    {
        Assert.Throws<InvalidOperationException>(() => TieredOAuthHelpers.ValidateIdPUri(idp));
    }

    [Theory]
    [InlineData("https://idp.example.com", true)]
    [InlineData("https://IDP.example.com/", true)]
    [InlineData("https://idp.example.com:443", true)]
    [InlineData("https://idp.example.com/other", false)]
    [InlineData("https://evil.example.com", false)]
    public void IsIdPAllowed_ComparesNormalizedBaseUrls(string idp, bool expected)
    {
        var options = new TieredOAuthAuthenticationOptions { AllowedIdPs = { "https://idp.example.com/" } };

        Assert.Equal(expected, options.IsIdPAllowed(idp));
    }

    [Fact]
    public void IsIdPAllowed_EmptyList_AllowsAny()
    {
        Assert.True(new TieredOAuthAuthenticationOptions().IsIdPAllowed("https://any.example.com"));
    }

    [Fact]
    public async Task Challenge_IdPNotAllowed_SendsNoRequest()
    {
        var interaction = Substitute.For<IIdentityServerInteractionService>();
        interaction.IsValidReturnUrl(Arg.Any<string>()).Returns(true);
        var udapClient = Substitute.For<IUdapClient>();
        var options = new TieredOAuthAuthenticationOptions { AllowedIdPs = { "https://idp.example.com" } };

        var returnUrl = "/connect/authorize/callback?client_id=c&idp=" + HttpUtility.UrlEncode("https://evil.example.com");

        await Assert.ThrowsAsync<InvalidOperationException>(() => TieredOAuthHelpers.BuildDynamicTieredOAuthOptions(
            interaction, udapClient, TieredOAuthAuthenticationDefaults.AuthenticationScheme, "/callback", returnUrl, options));

        await udapClient.DidNotReceiveWithAnyArgs().ResolveOpenIdConfig(default!, default);
    }

    [Fact]
    public async Task Challenge_NonHttpsIdP_SendsNoRequest()
    {
        var interaction = Substitute.For<IIdentityServerInteractionService>();
        interaction.IsValidReturnUrl(Arg.Any<string>()).Returns(true);
        var udapClient = Substitute.For<IUdapClient>();

        var returnUrl = "/connect/authorize/callback?client_id=c&idp=" + HttpUtility.UrlEncode("http://10.0.0.5/internal");

        await Assert.ThrowsAsync<InvalidOperationException>(() => TieredOAuthHelpers.BuildDynamicTieredOAuthOptions(
            interaction, udapClient, TieredOAuthAuthenticationDefaults.AuthenticationScheme, "/callback", returnUrl));

        await udapClient.DidNotReceiveWithAnyArgs().ResolveOpenIdConfig(default!, default);
    }
}
