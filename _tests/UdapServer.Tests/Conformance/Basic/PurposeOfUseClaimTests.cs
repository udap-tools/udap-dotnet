#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Duende.IdentityServer.Models;
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
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Configuration;
using Udap.Server.Validation;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Conformance.Basic;

/// <summary>
/// The purpose of use a client declares in its authorization extension (hl7-b2b) is validated at
/// the token endpoint; these tests prove it is also carried in the issued access token as a
/// repeated <c>purpose_of_use</c> claim (with the hl7-b2b <c>organization_id</c> /
/// <c>organization_name</c>), so a resource server can enforce it per request and forward it.
/// </summary>
[Collection("Udap.Auth.Server")]
public class PurposeOfUseClaimTests
{
    private const string Community = "udap://fhirlabs.net";
    private const string Treat = "urn:oid:2.16.840.1.113883.5.8#TREAT";
    private const string Payment = "urn:oid:2.16.840.1.113883.5.8#HPAYMT";
    private const string OrganizationId = "https://fhirlabs.net/fhir/r4";
    private const string OrganizationName = "FhirLabs";

    private readonly ITestOutputHelper _testOutputHelper;

    public PurposeOfUseClaimTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public async Task ClientCredentials_Hl7B2B_AddsPurposeOfUseAndOrganizationClaims_Verbatim()
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

        var tokenResponse = await RequestToken(pipeline, regResult.ClientId!, clientCert, B2B(Treat));
        Assert.False(tokenResponse.IsError, tokenResponse.Error);

        var jwt = new JwtSecurityToken(tokenResponse.AccessToken);
        Assert.Equal(new[] { Treat }, ClaimValues(jwt, UdapConstants.JwtClaimTypes.PurposeOfUse));
        Assert.Equal(OrganizationId, ClaimValues(jwt, UdapConstants.JwtClaimTypes.OrganizationId).Single());
        Assert.Equal(OrganizationName, ClaimValues(jwt, UdapConstants.JwtClaimTypes.OrganizationName).Single());

        // The community claim still rides alongside, both unprefixed.
        Assert.Equal(Community, ClaimValues(jwt, UdapConstants.JwtClaimTypes.UdapCommunity).Single());
        // Emitted under their own names, not under Duende's default "client_" client-claim prefix.
        Assert.DoesNotContain(jwt.Claims, c => c.Type is "client_purpose_of_use" or "client_organization_id" or "client_organization_name" or "client_udap_community");
    }

    [Fact]
    public async Task ClientCredentials_MultiplePurposes_OneClaimPerCode_SerializedAsJsonArray()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1
        });

        var clientCert = LoadClientCert();
        var regResult = await RegisterClientCredentialsClient(pipeline, clientCert);

        var tokenResponse = await RequestToken(pipeline, regResult.ClientId!, clientCert, B2B(Treat, Payment, Treat));
        Assert.False(tokenResponse.IsError, tokenResponse.Error);

        var jwt = new JwtSecurityToken(tokenResponse.AccessToken);
        Assert.Equal(new[] { Treat, Payment }, ClaimValues(jwt, UdapConstants.JwtClaimTypes.PurposeOfUse));

        // Resource servers read the raw payload: a repeated claim is a JSON array, and the values are
        // exactly what the client declared (no normalization at the token endpoint).
        var payload = ReadPayload(tokenResponse.AccessToken!);
        var purposes = payload.GetProperty(UdapConstants.JwtClaimTypes.PurposeOfUse);
        Assert.Equal(JsonValueKind.Array, purposes.ValueKind);
        Assert.Equal(new[] { Treat, Payment }, purposes.EnumerateArray().Select(e => e.GetString()).ToArray());
    }

    [Fact]
    public async Task ClientCredentials_FlagOff_NoPurposeOfUseClaims()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1,
            IncludePurposeOfUseClaims = false
        });

        var clientCert = LoadClientCert();
        var regResult = await RegisterClientCredentialsClient(pipeline, clientCert);

        var tokenResponse = await RequestToken(pipeline, regResult.ClientId!, clientCert, B2B(Treat));
        Assert.False(tokenResponse.IsError, tokenResponse.Error);

        var jwt = new JwtSecurityToken(tokenResponse.AccessToken);
        Assert.Empty(ClaimValues(jwt, UdapConstants.JwtClaimTypes.PurposeOfUse));
        Assert.Empty(ClaimValues(jwt, UdapConstants.JwtClaimTypes.OrganizationId));
        Assert.Empty(ClaimValues(jwt, UdapConstants.JwtClaimTypes.OrganizationName));
    }

    [Fact]
    public async Task ClientCredentials_NoExtension_NoPurposeOfUseClaims()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1
        });

        var clientCert = LoadClientCert();
        var regResult = await RegisterClientCredentialsClient(pipeline, clientCert);

        var tokenResponse = await RequestToken(pipeline, regResult.ClientId!, clientCert, extension: null);
        Assert.False(tokenResponse.IsError, tokenResponse.Error);

        var jwt = new JwtSecurityToken(tokenResponse.AccessToken);
        Assert.Empty(ClaimValues(jwt, UdapConstants.JwtClaimTypes.PurposeOfUse));
        Assert.Empty(ClaimValues(jwt, UdapConstants.JwtClaimTypes.OrganizationId));
    }

    [Fact]
    public async Task ClientCredentials_PurposeClaims_DoNotDependOnTheCommunityClaim()
    {
        // IncludeCommunityClaim off: the purpose path must still clear the client-claim prefix
        // and force AlwaysSendClientClaims on its own.
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1,
            IncludeCommunityClaim = false
        });

        var clientCert = LoadClientCert();
        var regResult = await RegisterClientCredentialsClient(pipeline, clientCert);

        var tokenResponse = await RequestToken(pipeline, regResult.ClientId!, clientCert, B2B(Treat));
        Assert.False(tokenResponse.IsError, tokenResponse.Error);

        var jwt = new JwtSecurityToken(tokenResponse.AccessToken);
        Assert.Equal(new[] { Treat }, ClaimValues(jwt, UdapConstants.JwtClaimTypes.PurposeOfUse));
        Assert.Empty(ClaimValues(jwt, UdapConstants.JwtClaimTypes.UdapCommunity));
        // Emitted under their own names, not under Duende's default "client_" client-claim prefix.
        Assert.DoesNotContain(jwt.Claims, c => c.Type is "client_purpose_of_use" or "client_organization_id" or "client_organization_name" or "client_udap_community");
    }

    [Fact]
    public async Task ClientCredentials_OrganizationNameOmitted_WhenNotDeclared()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1
        });

        var clientCert = LoadClientCert();
        var regResult = await RegisterClientCredentialsClient(pipeline, clientCert);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = OrganizationId,
            PurposeOfUse = new List<string> { Treat }
        };

        var tokenResponse = await RequestToken(pipeline, regResult.ClientId!, clientCert, b2b);
        Assert.False(tokenResponse.IsError, tokenResponse.Error);

        var jwt = new JwtSecurityToken(tokenResponse.AccessToken);
        Assert.Equal(OrganizationId, ClaimValues(jwt, UdapConstants.JwtClaimTypes.OrganizationId).Single());
        Assert.Empty(ClaimValues(jwt, UdapConstants.JwtClaimTypes.OrganizationName));
    }

    [Fact]
    public async Task ClientCredentials_ExtensionRejected_IssuesNoToken()
    {
        // A community that allows only TREAT refuses HPAYMT: the request fails before any claim
        // could be added, so the purpose path never runs on an invalid declaration.
        var communityValidator = new TestCommunityTokenValidator(
            Community,
            new CommunityValidationRules
            {
                RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
                AllowedPurposeOfUse = new HashSet<string> { Treat }
            });

        var pipeline = BuildPipeline(
            new ServerSettings
            {
                DefaultSystemScopes = "udap",
                DefaultUserScopes = "udap",
                SsraaVersion = SsraaVersion.V1_1
            },
            services => services.AddSingleton<ICommunityTokenValidator>(communityValidator));

        var clientCert = LoadClientCert();
        var regResult = await RegisterClientCredentialsClient(pipeline, clientCert);

        var tokenResponse = await RequestToken(pipeline, regResult.ClientId!, clientCert, B2B(Payment));

        Assert.True(tokenResponse.IsError);
        Assert.Equal("invalid_grant", tokenResponse.Error);
        Assert.Null(tokenResponse.AccessToken);
        _testOutputHelper.WriteLine($"error_description: {tokenResponse.ErrorDescription}");
    }

    #region Helpers

    private static HL7B2BAuthorizationExtension B2B(params string[] purposes) => new()
    {
        OrganizationId = OrganizationId,
        OrganizationName = OrganizationName,
        PurposeOfUse = purposes.ToList()
    };

    private static string[] ClaimValues(JwtSecurityToken jwt, string claimType) =>
        jwt.Claims.Where(c => c.Type == claimType).Select(c => c.Value).ToArray();

    private static JsonElement ReadPayload(string accessToken)
    {
        var segment = accessToken.Split('.')[1].Replace('-', '+').Replace('_', '/');
        segment = segment.PadRight(segment.Length + (4 - segment.Length % 4) % 4, '=');
        return JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(segment))).RootElement;
    }

    private static X509Certificate2 LoadClientCert()
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        return new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
    }

    private static async Task<Duende.IdentityModel.Client.TokenResponse> RequestToken(
        UdapAuthServerPipeline pipeline,
        string clientId,
        X509Certificate2 clientCert,
        HL7B2BAuthorizationExtension? extension)
    {
        var builder = AccessTokenRequestForClientCredentialsBuilder.Create(
                clientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs");

        if (extension != null)
        {
            builder.WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, extension);
        }

        return await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(builder.Build("RS384"));
    }

    private UdapAuthServerPipeline BuildPipeline(
        ServerSettings serverSettings,
        Action<IServiceCollection>? configureServices = null)
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

            configureServices?.Invoke(services);
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

    /// <summary>Community validator that supplies rules and otherwise always succeeds.</summary>
    private sealed class TestCommunityTokenValidator : ICommunityTokenValidator
    {
        private readonly string _community;
        private readonly CommunityValidationRules _rules;

        public TestCommunityTokenValidator(string community, CommunityValidationRules rules)
        {
            _community = community;
            _rules = rules;
        }

        public bool AppliesToCommunity(string communityName) => communityName == _community;

        public CommunityValidationRules? GetValidationRules(string? grantType) => _rules;

        public Task<AuthorizationExtensionValidationResult> ValidateAsync(
            UdapAuthorizationExtensionValidationContext context)
            => Task.FromResult(AuthorizationExtensionValidationResult.Success());
    }

    #endregion
}
