#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Client.Extensions;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using Udap.Server.Validation;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Conformance.Basic;

[Collection("Udap.Auth.Server")]
public class CommunityClaimTests
{
    private const string Community = "udap://fhirlabs.net";
    private readonly ITestOutputHelper _testOutputHelper;

    public CommunityClaimTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public async Task ClientCredentials_FlagOn_AddsUdapCommunityClaim_AndRegistrationProperty()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1,
            IncludeCommunityClaim = true
        });

        var clientCert = LoadClientCert();
        var regResult = await RegisterClientCredentialsClient(pipeline, clientCert);

        // Registration wrote the community name to the client property.
        var client = pipeline.Clients.Single(c => c.ClientId == regResult.ClientId);
        Assert.Equal(Community, client.Properties[Udap.Server.Storage.UdapServerConstants.ClientPropertyConstants.Community]);

        var tokenResponse = await RequestClientCredentialsToken(pipeline, regResult.ClientId!, clientCert);
        Assert.False(tokenResponse.IsError, tokenResponse.Error);

        var communityClaim = ReadClaim(tokenResponse.AccessToken!, UdapConstants.JwtClaimTypes.UdapCommunity);
        Assert.Equal(Community, communityClaim);
    }

    [Fact]
    public async Task ClientCredentials_FlagOff_NoUdapCommunityClaim_NorProperty()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1,
            IncludeCommunityClaim = false
        });

        var clientCert = LoadClientCert();
        var regResult = await RegisterClientCredentialsClient(pipeline, clientCert);

        var client = pipeline.Clients.Single(c => c.ClientId == regResult.ClientId);
        Assert.False(client.Properties.ContainsKey(Udap.Server.Storage.UdapServerConstants.ClientPropertyConstants.Community));

        var tokenResponse = await RequestClientCredentialsToken(pipeline, regResult.ClientId!, clientCert);
        Assert.False(tokenResponse.IsError, tokenResponse.Error);

        Assert.Null(ReadClaim(tokenResponse.AccessToken!, UdapConstants.JwtClaimTypes.UdapCommunity));
    }

    [Fact]
    public async Task ClientCredentials_FlagOn_CommunityRenamed_ClaimReflectsCurrentName()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1,
            IncludeCommunityClaim = true
        });

        var clientCert = LoadClientCert();
        var regResult = await RegisterClientCredentialsClient(pipeline, clientCert);

        var firstToken = await RequestClientCredentialsToken(pipeline, regResult.ClientId!, clientCert);
        Assert.False(firstToken.IsError, firstToken.Error);
        Assert.Equal(Community, ReadClaim(firstToken.AccessToken!, UdapConstants.JwtClaimTypes.UdapCommunity));

        // Rename the community after registration. The claim is resolved from the stored
        // community id at token time, so the next token must reflect the new name.
        const string renamed = "udap://renamed.fhirlabs.net";
        pipeline.Communities.First().Name = renamed;

        var secondToken = await RequestClientCredentialsToken(pipeline, regResult.ClientId!, clientCert);
        Assert.False(secondToken.IsError, secondToken.Error);
        Assert.Equal(renamed, ReadClaim(secondToken.AccessToken!, UdapConstants.JwtClaimTypes.UdapCommunity));
    }

    [Fact]
    public async Task AuthorizationCode_FlagOn_AddsUdapCommunityClaim()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1,
            RequireConsent = false,
            IncludeCommunityClaim = true
        });

        var clientCert = LoadClientCert();

        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("community claim auth code test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest(
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>());

        pipeline.BrowserClient.AllowAutoRedirect = true;

        var response = await pipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.NotNull(resultDocument);
        var clientId = resultDocument!.ClientId!;

        await pipeline.LoginAsync("bob");

        var url = pipeline.CreateAuthorizeUrl(
            clientId: clientId,
            responseType: "code",
            scope: "openid",
            redirectUri: "https://code_client/callback",
            state: Guid.NewGuid().ToString(),
            nonce: Guid.NewGuid().ToString());

        pipeline.BrowserClient.AllowAutoRedirect = false;
        response = await pipeline.BrowserClient.GetAsync(url);
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.Contains(queryParams, p => p.Key == "code");

        var tokenRequest = AccessTokenRequestForAuthorizationCodeBuilder.Create(
                clientId,
                "https://server/connect/token",
                clientCert,
                "https://code_client/callback",
                queryParams.First(p => p.Key == "code").Value)
            .Build();

        var udapClient = pipeline.Resolve<IUdapClient>();
        var tokenResponse = await udapClient.ExchangeCodeForTokenResponse(tokenRequest);

        Assert.NotNull(tokenResponse.AccessToken);
        Assert.Equal(Community, ReadClaim(tokenResponse.AccessToken!, UdapConstants.JwtClaimTypes.UdapCommunity));
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

    private static string? ReadClaim(string accessToken, string claimType)
    {
        var jwt = new JwtSecurityToken(accessToken);
        return jwt.Claims.FirstOrDefault(c => c.Type == claimType)?.Value;
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

    private UdapAuthServerPipeline BuildPipeline(ServerSettings serverSettings)
    {
        var pipeline = new UdapAuthServerPipeline();

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

        pipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        pipeline.IdentityScopes.Add(new IdentityResources.Profile());
        pipeline.ApiScopes.AddRange(new HL7SmartScopeExpander().ExpandToApiScopes("system/Patient.rs"));

        pipeline.Users.Add(new Duende.IdentityServer.Test.TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims =
            [
                new System.Security.Claims.Claim("name", "Bob Loblaw"),
                new System.Security.Claims.Claim("email", "bob@loblaw.com"),
                new System.Security.Claims.Claim("role", "Attorney")
            ]
        });

        return pipeline;
    }

    private static async Task<UdapDynamicClientRegistrationDocument> RegisterClientCredentialsClient(
        UdapAuthServerPipeline pipeline,
        X509Certificate2 clientCert)
    {
        var udapClient = pipeline.Resolve<IUdapClient>();

        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
        {
            RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint
        };

        var regResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regResult.GetError());

        return regResult;
    }

    #endregion
}
