#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Claims;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Test;
using Duende.IdentityServer.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Udap.Server.Security.Authentication.TieredOAuth;
using Udap.UI;
using Udap.UI.Options;
using Udap.UI.Services;
using Xunit;

namespace UdapServer.Tests.UI;

public class UdapUIServicesTests
{
    [Theory]
    [InlineData("/", true)]
    [InlineData("/connect/authorize/callback?client_id=a", true)]
    [InlineData("~/", true)]
    [InlineData("~/home", true)]
    [InlineData("//evil.example", false)]
    [InlineData("/\\evil.example", false)]
    [InlineData("~//evil.example", false)]
    [InlineData("https://evil.example/", false)]
    [InlineData("/path\r\nheader", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsLocalUrl_MatchesUrlHelperRules(string? url, bool expected)
    {
        Assert.Equal(expected, UdapReturnUrl.IsLocalUrl(url));
    }

    [Fact]
    public void ScopeList_FirstDisplay_ChecksEverythingAndAddsOfflineAccess()
    {
        var scopes = UdapScopeListBuilder.Build(CreateResources(), new[] { "fhir-api" }, null, new UdapUIConsentOptions());

        Assert.All(scopes.IdentityScopes, s => Assert.True(s.Checked));
        Assert.Contains(scopes.IdentityScopes, s => s.Name == "openid" && s.Required);

        var patientRead = Assert.Single(scopes.ApiScopes, s => s.Value == "patient/*.read");
        Assert.True(patientRead.Checked);
        Assert.Equal("fhir-api", Assert.Single(patientRead.Resources).Name);

        var offline = Assert.Single(scopes.ApiScopes, s => s.Value == IdentityServerConstants.StandardScopes.OfflineAccess);
        Assert.Equal("Offline Access", offline.DisplayName);
    }

    [Fact]
    public void ScopeList_Redisplay_KeepsOnlyPreviousSelectionsAndRequiredScopes()
    {
        var scopes = UdapScopeListBuilder.Build(CreateResources(), null, Array.Empty<string>(), new UdapUIConsentOptions());

        // openid is required, so it stays checked even when nothing was selected
        Assert.True(Assert.Single(scopes.IdentityScopes, s => s.Name == "openid").Checked);
        Assert.False(Assert.Single(scopes.IdentityScopes, s => s.Name == "profile").Checked);
        Assert.All(scopes.ApiScopes, s => Assert.False(s.Checked));
    }

    [Fact]
    public void ScopeList_OfflineAccessDisabled_IsNotOffered()
    {
        var scopes = UdapScopeListBuilder.Build(CreateResources(), null, null, new UdapUIConsentOptions { EnableOfflineAccess = false });

        Assert.DoesNotContain(scopes.ApiScopes, s => s.Value == IdentityServerConstants.StandardScopes.OfflineAccess);
    }

    [Theory]
    [InlineData("maybe", "Invalid selection")]
    [InlineData(null, "Invalid selection")]
    [InlineData("yes", "You must pick at least one permission")]
    public void ConsentDecision_InvalidSelection_ReturnsError(string? button, string expectedError)
    {
        var (response, error) = UdapScopeListBuilder.Decide(button, Array.Empty<string>(), true, null, new UdapUIConsentOptions());

        Assert.Null(response);
        Assert.Equal(expectedError, error);
    }

    [Fact]
    public void ConsentDecision_No_DeniesAccess()
    {
        var (response, error) = UdapScopeListBuilder.Decide("no", null, false, null, new UdapUIConsentOptions());

        Assert.Null(error);
        Assert.Equal(InteractionError.AccessDenied, response!.Error);
    }

    [Fact]
    public void ConsentDecision_Yes_StripsOfflineAccessWhenDisabled()
    {
        var (response, _) = UdapScopeListBuilder.Decide(
            "yes",
            new[] { "openid", IdentityServerConstants.StandardScopes.OfflineAccess },
            true,
            "my phone",
            new UdapUIConsentOptions { EnableOfflineAccess = false });

        Assert.Equal(new[] { "openid" }, response!.ScopesValuesConsented);
        Assert.True(response.RememberConsent);
        Assert.Equal("my phone", response.Description);
    }

    [Fact]
    public async Task Login_BuildContext_CarriesUdapIdpHintToTieredProvider()
    {
        var schemes = Substitute.For<IAuthenticationSchemeProvider>();
        schemes.GetAllSchemesAsync().Returns(new[]
        {
            new AuthenticationScheme(TieredOAuthAuthenticationDefaults.AuthenticationScheme, "UDAP Tiered OAuth", typeof(TieredOAuthAuthenticationHandler)),
            new AuthenticationScheme("cookie", null, typeof(TieredOAuthAuthenticationHandler))
        });

        var service = CreateLoginService(schemeProvider: schemes);
        const string returnUrl = "/connect/authorize/callback?client_id=app&idp=https%3A%2F%2Fidp1.example%2Fidp";

        var context = await service.BuildLoginContextAsync(new DefaultHttpContext(), returnUrl);

        var tiered = Assert.Single(context.ExternalProviders);
        Assert.True(tiered.IsTieredOAuth);
        Assert.Equal("https://idp1.example/idp", tiered.TieredOAuthIdp);
        Assert.True(context.EnableLocalLogin);
        Assert.False(context.IsExternalLoginOnly);
    }

    [Fact]
    public async Task Login_BuildContext_ClientWithoutLocalLogin_IsExternalOnly()
    {
        var interaction = Substitute.For<IIdentityServerInteractionService>();
        interaction.GetAuthorizationContextAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new AuthorizationRequest { Client = new Client { ClientId = "app", EnableLocalLogin = false } });

        var schemes = Substitute.For<IAuthenticationSchemeProvider>();
        schemes.GetAllSchemesAsync().Returns(new[]
        {
            new AuthenticationScheme(TieredOAuthAuthenticationDefaults.AuthenticationScheme, "UDAP Tiered OAuth", typeof(TieredOAuthAuthenticationHandler))
        });

        var service = CreateLoginService(interaction, schemes);

        var context = await service.BuildLoginContextAsync(new DefaultHttpContext(), "/connect/authorize/callback?client_id=app");

        Assert.True(context.IsExternalLoginOnly);
        Assert.Equal(TieredOAuthAuthenticationDefaults.AuthenticationScheme, context.ExternalLoginScheme);
        Assert.Equal("app", context.Client!.ClientId);
    }

    [Fact]
    public async Task Login_InvalidCredentials_ShowsPageAndRaisesFailureEvent()
    {
        var events = Substitute.For<IEventService>();
        var service = CreateLoginService(events: events);

        var result = await service.SignInLocalAsync(new DefaultHttpContext(), "alice", "wrong", false, "/");

        Assert.True(result.IsShowPage);
        Assert.Equal("Invalid username or password", result.Error);
        await events.Received(1).RaiseAsync(Arg.Is<Event>(e => e is UserLoginFailureEvent), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Login_CancelWithoutAuthorizeRequest_GoesHome()
    {
        var result = await CreateLoginService().CancelAsync(new DefaultHttpContext(), "/not-an-authorize-request");

        Assert.Equal(UdapInteractionResultKind.Redirect, result.Kind);
        Assert.Equal("~/", result.Url);
    }

    [Fact]
    public async Task UserStoreAdapter_WrapsTestUserStore()
    {
        var store = new TestUserStoreAdapter(new TestUserStore(new List<TestUser>
        {
            new() { SubjectId = "1", Username = "alice", Password = "alice", Claims = new[] { new Claim("name", "Alice") } }
        }));

        Assert.Null(await store.ValidateCredentialsAsync("alice", "nope"));
        var alice = await store.ValidateCredentialsAsync("alice", "alice");
        Assert.Equal("1", alice!.SubjectId);
        Assert.Contains(alice.Claims, c => c is { Type: "name", Value: "Alice" });

        var provisioned = await store.AutoProvisionAsync("idp1", "ext-9", new[] { new Claim("name", "Bob") });
        Assert.Equal(provisioned.SubjectId, (await store.FindByExternalProviderAsync("idp1", "ext-9"))!.SubjectId);
    }

    [Fact]
    public void AddUdapUI_RegistersServicesAndKeepsHostUserStore()
    {
        var hostStore = Substitute.For<IUdapUserStore>();
        var services = new ServiceCollection();
        services.AddSingleton(hostStore);
        services.AddUdapUI(o => o.Login.AllowRememberLogin = false);

        Assert.Contains(services, d => d.ServiceType == typeof(IUdapLoginService));
        Assert.Contains(services, d => d.ServiceType == typeof(IUdapExternalLoginService));
        Assert.Contains(services, d => d.ServiceType == typeof(IUdapLogoutService));
        Assert.Contains(services, d => d.ServiceType == typeof(IUdapConsentService));
        Assert.Single(services, d => d.ServiceType == typeof(IUdapUserStore));

        using var provider = services.BuildServiceProvider();
        Assert.Same(hostStore, provider.GetRequiredService<IUdapUserStore>());
        Assert.False(provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<UdapUIOptions>>().Value.Login.AllowRememberLogin);
    }

    private static UdapLoginService CreateLoginService(
        IIdentityServerInteractionService? interaction = null,
        IAuthenticationSchemeProvider? schemeProvider = null,
        IEventService? events = null)
    {
        var providers = Substitute.For<IIdentityProviderStore>();
        providers.GetAllSchemeNamesAsync(Arg.Any<CancellationToken>()).Returns(Array.Empty<IdentityProviderName>());

        var users = Substitute.For<IUdapUserStore>();
        users.ValidateCredentialsAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((UdapUser?)null);

        return new UdapLoginService(
            interaction ?? Substitute.For<IIdentityServerInteractionService>(),
            schemeProvider ?? Substitute.For<IAuthenticationSchemeProvider>(),
            providers,
            events ?? Substitute.For<IEventService>(),
            users,
            Microsoft.Extensions.Options.Options.Create(new UdapUIOptions()));
    }

    private static ResourceValidationResult CreateResources()
    {
        var resources = new Resources(
            new IdentityResource[] { new IdentityResources.OpenId(), new IdentityResources.Profile() },
            new[] { new ApiResource("fhir-api") { Scopes = { "patient/*.read" } } },
            new[] { new ApiScope("patient/*.read", "Read your health records") })
        {
            OfflineAccess = true
        };

        return new ResourceValidationResult(resources);
    }
}
