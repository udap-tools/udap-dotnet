#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Udap.Client;
using Udap.Common.Certificates;
using Udap.Server.Security.Authentication.TieredOAuth;
using Udap.Server.Storage.Stores;
using Xunit;

namespace UdapServer.Tests.Conformance.Tiered;

public class TieredOAuthCallbackUrlTests
{
    [Fact]
    public async Task Callback_IsBuiltFromConfiguredBaseUrl_NotHostHeader()
    {
        var handler = await CreateHandler("https://auth.example.com/", host: "evil.example");

        Assert.Equal("https://auth.example.com/federation/udap-tiered/signin", handler.RedirectUri());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-url")]
    public async Task Callback_WithoutConfiguredBaseUrl_Fails(string? baseUrl)
    {
        var handler = await CreateHandler(baseUrl, host: "auth.example.com");

        Assert.Throws<InvalidOperationException>(() => handler.RedirectUri());
    }

    [Fact]
    public void AddUdapServer_SetsCallbackBaseUrlFromServerBaseUrl()
    {
        var services = new ServiceCollection();
        services.AddUdapServer("https://auth.example.com", "FhirLabsApi");
        services.AddAuthentication().AddScheme<TieredOAuthAuthenticationOptions, TieredOAuthAuthenticationHandler>(
            TieredOAuthAuthenticationDefaults.AuthenticationScheme, o => o.SignInScheme = "external");

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<TieredOAuthAuthenticationOptions>>()
            .Get(TieredOAuthAuthenticationDefaults.AuthenticationScheme);

        Assert.Equal("https://auth.example.com", options.CallbackBaseUrl);
    }

    [Fact]
    public void AddUdapServer_KeepsExplicitCallbackBaseUrl()
    {
        var services = new ServiceCollection();
        services.AddUdapServer("https://auth.example.com", "FhirLabsApi");
        services.AddAuthentication().AddScheme<TieredOAuthAuthenticationOptions, TieredOAuthAuthenticationHandler>(
            TieredOAuthAuthenticationDefaults.AuthenticationScheme, o =>
            {
                o.SignInScheme = "external";
                o.CallbackBaseUrl = "https://public.example.com";
            });

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<TieredOAuthAuthenticationOptions>>()
            .Get(TieredOAuthAuthenticationDefaults.AuthenticationScheme);

        Assert.Equal("https://public.example.com", options.CallbackBaseUrl);
    }

    [Fact]
    public void AddTieredOAuth_ReadsCallbackBaseUrlAndAllowedIdPsFromConfiguration()
    {
        var options = ResolveTieredOptions(new Dictionary<string, string?>
        {
            ["TieredOAuth:CallbackBaseUrl"] = "https://gateway.example.com",
            ["TieredOAuth:AllowedIdPs:0"] = "https://idp1.example.com",
            ["TieredOAuth:AllowedIdPs:1"] = "https://idp2.example.com/"
        });

        Assert.Equal("https://gateway.example.com", options.CallbackBaseUrl);
        Assert.Equal(new[] { "https://idp1.example.com", "https://idp2.example.com/" }, options.AllowedIdPs);
        Assert.True(options.IsIdPAllowed("https://idp2.example.com"));
        Assert.False(options.IsIdPAllowed("https://other.example.com"));
    }

    [Fact]
    public void AddTieredOAuth_CodeWinsOverConfiguration()
    {
        var options = ResolveTieredOptions(
            new Dictionary<string, string?> { ["TieredOAuth:CallbackBaseUrl"] = "https://gateway.example.com" },
            o => o.CallbackBaseUrl = "https://from-code.example.com");

        Assert.Equal("https://from-code.example.com", options.CallbackBaseUrl);
    }

    [Fact]
    public void AddTieredOAuth_WithoutConfiguration_FallsBackToServerBaseUrl()
    {
        var options = ResolveTieredOptions(new Dictionary<string, string?>());

        Assert.Equal("https://auth.example.com", options.CallbackBaseUrl);
        Assert.Empty(options.AllowedIdPs);
    }

    [Fact]
    public void AddTieredOAuth_NoIConfigurationRegistered_DoesNotThrow()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddUdapServer("https://auth.example.com", "FhirLabsApi");
        services.AddAuthentication().AddTieredOAuth(o => o.SignInScheme = "external");

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<TieredOAuthAuthenticationOptions>>()
            .Get(TieredOAuthAuthenticationDefaults.AuthenticationScheme);

        Assert.Equal("https://auth.example.com", options.CallbackBaseUrl);
    }

    private static TieredOAuthAuthenticationOptions ResolveTieredOptions(
        Dictionary<string, string?> configurationValues,
        Action<TieredOAuthAuthenticationOptions>? configure = null)
    {
        var configuration = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(configurationValues)
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<Microsoft.Extensions.Configuration.IConfiguration>(configuration);
        services.AddUdapServer("https://auth.example.com", "FhirLabsApi");
        services.AddAuthentication().AddTieredOAuth(o =>
        {
            o.SignInScheme = "external";
            configure?.Invoke(o);
        });

        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IOptionsMonitor<TieredOAuthAuthenticationOptions>>()
            .Get(TieredOAuthAuthenticationDefaults.AuthenticationScheme);
    }

    private static async Task<TestableHandler> CreateHandler(string? callbackBaseUrl, string host)
    {
        var options = new TieredOAuthAuthenticationOptions { CallbackBaseUrl = callbackBaseUrl };
        var monitor = Substitute.For<IOptionsMonitor<TieredOAuthAuthenticationOptions>>();
        monitor.Get(Arg.Any<string>()).Returns(options);

        var handler = new TestableHandler(
            monitor,
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            Substitute.For<IUdapClient>(),
            Substitute.For<IPrivateCertificateStore>(),
            Substitute.For<IUdapClientRegistrationStore>());

        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString(host);

        await handler.InitializeAsync(
            new AuthenticationScheme(TieredOAuthAuthenticationDefaults.AuthenticationScheme, null, typeof(TestableHandler)),
            context);

        return handler;
    }

    private sealed class TestableHandler : TieredOAuthAuthenticationHandler
    {
        public TestableHandler(
            IOptionsMonitor<TieredOAuthAuthenticationOptions> options,
            Microsoft.Extensions.Logging.ILoggerFactory logger,
            UrlEncoder encoder,
            IUdapClient udapClient,
            IPrivateCertificateStore certificateStore,
            IUdapClientRegistrationStore udapClientRegistrationStore)
            : base(options, logger, encoder, udapClient, certificateStore, udapClientRegistrationStore)
        {
        }

        public string RedirectUri() => BuildCallbackUrl();
    }
}
