#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Client.Extensions;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Server.Configuration;
using Udap.Server.Validation;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Conformance.Basic;

/// <summary>
/// The optional per-community chain-length limit at registration and at the token endpoint.
/// The fhirlabs.net client chain is root -> intermediate -> leaf: three certificates.
/// </summary>
[Collection("Udap.Auth.Server")]
public class ChainLengthLimitTests
{
    private const string Community = "udap://fhirlabs.net";
    private readonly ITestOutputHelper _testOutputHelper;

    public ChainLengthLimitTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public async Task Registration_IsRejected_WhenTheCommunityLimitIsShorterThanTheChain()
    {
        var chainOptions = new TrustChainValidatorOptions
        {
            Communities = { new CommunityChainPolicy { Community = Community, MaxChainLength = 2 } }
        };
        var pipeline = BuildPipeline(chainOptions);

        var regResult = await RegisterClientCredentialsClient(pipeline, LoadClientCert());

        Assert.NotNull(regResult.GetError());
        Assert.Empty(pipeline.Clients);
    }

    [Fact]
    public async Task Registration_IsRejected_WhenTheGlobalLimitIsShorterThanTheChain()
    {
        var pipeline = BuildPipeline(new TrustChainValidatorOptions { MaxChainLength = 2 });

        var regResult = await RegisterClientCredentialsClient(pipeline, LoadClientCert());

        Assert.NotNull(regResult.GetError());
    }

    [Fact]
    public async Task RegistrationAndToken_Succeed_WhenTheChainFitsTheCommunityLimit()
    {
        var chainOptions = new TrustChainValidatorOptions
        {
            MaxChainLength = 2,
            Communities = { new CommunityChainPolicy { Community = Community, MaxChainLength = 3 } }
        };
        var pipeline = BuildPipeline(chainOptions);
        var clientCert = LoadClientCert();

        var regResult = await RegisterClientCredentialsClient(pipeline, clientCert);
        Assert.Null(regResult.GetError());

        var tokenResponse = await RequestClientCredentialsToken(pipeline, regResult.ClientId!, clientCert);
        Assert.False(tokenResponse.IsError, tokenResponse.Error);
    }

    [Fact]
    public async Task Token_IsRejected_WhenTheCommunityLimitIsShorterThanTheChain()
    {
        // Register without a limit, then set one for the client's community: the client assertion at the
        // token endpoint is validated against the community the client registered in.
        var chainOptions = new TrustChainValidatorOptions();
        var pipeline = BuildPipeline(chainOptions);
        var clientCert = LoadClientCert();

        var regResult = await RegisterClientCredentialsClient(pipeline, clientCert);
        Assert.Null(regResult.GetError());

        chainOptions.Communities.Add(new CommunityChainPolicy { Community = Community, MaxChainLength = 2 });

        var tokenResponse = await RequestClientCredentialsToken(pipeline, regResult.ClientId!, clientCert);
        Assert.True(tokenResponse.IsError);
        Assert.Equal("invalid_client", tokenResponse.Error);
    }

    #region Helpers

    private static X509Certificate2 LoadClientCert()
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        return new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
    }

    private static async Task<Duende.IdentityModel.Client.TokenResponse> RequestClientCredentialsToken(
        UdapAuthServerPipeline pipeline,
        string clientId,
        X509Certificate2 clientCert)
    {
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                clientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        return await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);
    }

    private UdapAuthServerPipeline BuildPipeline(TrustChainValidatorOptions chainOptions)
    {
        var pipeline = new UdapAuthServerPipeline();
        var serverSettings = new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1
        };

#if NET9_0_OR_GREATER
        var sureFhirLabsAnchor = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#else
        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#endif

        pipeline.OnPostConfigureServices += services =>
        {
            services.AddSingleton(serverSettings);
            services.AddSingleton<IOptionsMonitor<ServerSettings>>(
                new OptionsMonitorForTests<ServerSettings>(serverSettings));

            // Replaces the pipeline's validator with one that applies the chain-length options.
            services.AddSingleton(sp => new TrustChainValidator(
                TrustChainValidator.DefaultProblemFlags,
                false,
                sp.GetRequiredService<ILogger<TrustChainValidator>>(),
                null,
                null,
                TrustChainValidator.DefaultDownloadTimeout,
                chainOptions));

            services.AddSingleton<IOptionsMonitor<UdapClientOptions>>(
                new OptionsMonitorForTests<UdapClientOptions>(
                    new UdapClientOptions
                    {
                        ClientName = "Mock Client",
                        Contacts = new HashSet<string>
                        {
                            "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
                        }
                    }));

            services.AddScoped<IUdapClient>(sp => new UdapClient(
                pipeline.BrowserClient,
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));
        };

        pipeline.OnPreConfigureServices += (_, s) =>
        {
            s.AddSingleton(pipeline.Clients);
        };

        pipeline.Initialize(enableLogging: true);
        pipeline.BrowserClient.AllowAutoRedirect = false;

        pipeline.Communities.Add(new Community
        {
            Name = Community,
            Enabled = true,
            Default = true,
            Anchors =
            [
                new Anchor(sureFhirLabsAnchor, Community)
                {
                    BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                    EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                    Name = sureFhirLabsAnchor.Subject,
                    Enabled = true,
                    Intermediates = new List<Intermediate>
                    {
                        new Intermediate(intermediateCert)
                        {
                            BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                            Name = intermediateCert.Subject,
                            Enabled = true
                        }
                    }
                }
            ]
        });

        pipeline.ApiScopes.AddRange(new HL7SmartScopeExpander().ExpandToApiScopes("system/Patient.rs"));

        return pipeline;
    }

    private static async Task<Udap.Model.Registration.UdapDynamicClientRegistrationDocument> RegisterClientCredentialsClient(
        UdapAuthServerPipeline pipeline,
        X509Certificate2 clientCert)
    {
        var udapClient = pipeline.Resolve<IUdapClient>();

        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
        {
            RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint
        };

        return await udapClient.RegisterClientCredentialsClient(clientCert, "system/Patient.rs");
    }

    #endregion
}
