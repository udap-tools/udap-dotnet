#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography.X509Certificates;
using Duende.IdentityModel.Client;
using Duende.IdentityServer.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Udap.Client;
using Udap.Client.Extensions;
using Udap.Client.Configuration;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using Udap.Server.Validation;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Conformance.Basic;

[Collection("Udap.Auth.Server")]
public class AuthorizationExtensionEnforcementTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    public AuthorizationExtensionEnforcementTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public async Task TokenRequest_WithRequiredB2B_WithValidExtension_Succeeds()
    {
        var communityValidator = new TestCommunityTokenValidator(
            "udap://fhirlabs.net",
            new CommunityValidationRules
            {
                RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B }
            });

        var pipeline = BuildPipeline(
            new ServerSettings
            {
                DefaultSystemScopes = "udap",
                DefaultUserScopes = "udap",
                SsraaVersion = SsraaVersion.V1_1
            },
            configureServices: services =>
            {
                services.AddSingleton<ICommunityTokenValidator>(communityValidator);
            });

#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var regResult = await RegisterClient(pipeline, clientCert);

        var b2b = new HL7B2BAuthorizationExtension
        {
            SubjectId = "urn:oid:2.16.840.1.113883.4.6#1234567890",
            OrganizationId = "https://fhirlabs.net/fhir/r4",
            OrganizationName = "FhirLabs",
            PurposeOfUse = new List<string> { "urn:oid:2.16.840.1.113883.5.8#TREAT" }
        };

        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, b2b)
            .Build("RS384");

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.False(tokenResponse.IsError, tokenResponse.Error);
        Assert.Equal("system/Patient.rs", tokenResponse.Scope);
    }

    [Fact]
    public async Task TokenRequest_WithRequiredB2B_WithoutExtension_Fails()
    {
        var communityValidator = new TestCommunityTokenValidator(
            "udap://fhirlabs.net",
            new CommunityValidationRules
            {
                RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B }
            });

        var pipeline = BuildPipeline(
            new ServerSettings
            {
                DefaultSystemScopes = "udap",
                DefaultUserScopes = "udap",
                SsraaVersion = SsraaVersion.V1_1
            },
            configureServices: services =>
            {
                services.AddSingleton<ICommunityTokenValidator>(communityValidator);
            });

#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var regResult = await RegisterClient(pipeline, clientCert);

        // Token request WITHOUT extension
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.HttpStatusCode);
        Assert.Equal("invalid_grant", tokenResponse.Error);
        Assert.NotNull(tokenResponse.ErrorDescription);
        Assert.Contains("hl7-b2b", tokenResponse.ErrorDescription);
    }

    [Fact]
    public async Task TokenRequest_WithRequiredB2B_WithInvalidExtension_MissingOrganizationId_Fails()
    {
        var communityValidator = new TestCommunityTokenValidator(
            "udap://fhirlabs.net",
            new CommunityValidationRules
            {
                RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B }
            });

        var pipeline = BuildPipeline(
            new ServerSettings
            {
                DefaultSystemScopes = "udap",
                DefaultUserScopes = "udap",
                SsraaVersion = SsraaVersion.V1_1
            },
            configureServices: services =>
            {
                services.AddSingleton<ICommunityTokenValidator>(communityValidator);
            });

#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var regResult = await RegisterClient(pipeline, clientCert);

        // B2B extension with missing organization_id
        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = null,
            PurposeOfUse = new List<string> { "urn:oid:2.16.840.1.113883.5.8#TREAT" }
        };

        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, b2b)
            .Build("RS384");

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.HttpStatusCode);
        Assert.Equal("invalid_grant", tokenResponse.Error);
        Assert.NotNull(tokenResponse.ErrorDescription);
        Assert.Contains("organization_id", tokenResponse.ErrorDescription);
    }

    [Fact]
    public async Task TokenRequest_NoCommunityValidator_WithoutExtension_Succeeds()
    {
        // No community validator registered — no enforcement
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1
        });

#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var regResult = await RegisterClient(pipeline, clientCert);

        // Token request without any extension — should work when nothing is required
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.False(tokenResponse.IsError, tokenResponse.Error);
        Assert.Equal("system/Patient.rs", tokenResponse.Scope);
    }

    [Fact]
    public async Task TokenRequest_CommunityValidator_RequiresB2B_WithoutExtension_Fails()
    {
        var communityValidator = new TestCommunityTokenValidator(
            "udap://fhirlabs.net",
            new CommunityValidationRules
            {
                RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B }
            });

        var pipeline = BuildPipeline(
            new ServerSettings
            {
                DefaultSystemScopes = "udap",
                DefaultUserScopes = "udap",
                SsraaVersion = SsraaVersion.V1_1
            },
            configureServices: services =>
            {
                services.AddSingleton<ICommunityTokenValidator>(communityValidator);
            });

#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var regResult = await RegisterClient(pipeline, clientCert);

        // Token request without extension — community validator requires it
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.HttpStatusCode);
        Assert.Equal("invalid_grant", tokenResponse.Error);
        Assert.NotNull(tokenResponse.ErrorDescription);
        Assert.Contains("hl7-b2b", tokenResponse.ErrorDescription);
    }

    [Fact]
    public async Task TokenRequest_CommunityValidator_RequiresB2B_WithValidExtension_Succeeds()
    {
        var communityValidator = new TestCommunityTokenValidator(
            "udap://fhirlabs.net",
            new CommunityValidationRules
            {
                RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
                AllowedPurposeOfUse = new HashSet<string> { "urn:oid:2.16.840.1.113883.5.8#TREAT" }
            });

        var pipeline = BuildPipeline(
            new ServerSettings
            {
                DefaultSystemScopes = "udap",
                DefaultUserScopes = "udap",
                SsraaVersion = SsraaVersion.V1_1
            },
            configureServices: services =>
            {
                services.AddSingleton<ICommunityTokenValidator>(communityValidator);
            });

#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var regResult = await RegisterClient(pipeline, clientCert);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "https://fhirlabs.net/fhir/r4",
            OrganizationName = "FhirLabs",
            PurposeOfUse = new List<string> { "urn:oid:2.16.840.1.113883.5.8#TREAT" }
        };

        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, b2b)
            .Build("RS384");

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.False(tokenResponse.IsError, tokenResponse.Error);
        Assert.Equal("system/Patient.rs", tokenResponse.Scope);
    }

    [Fact]
    public async Task TokenRequest_CustomValidator_Overrides_DefaultBehavior()
    {
        var customValidator = Substitute.For<IUdapAuthorizationExtensionValidator>();
        customValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(AuthorizationExtensionValidationResult.Failure("custom_error", "Custom validator rejected"));

        var pipeline = BuildPipeline(
            new ServerSettings
            {
                DefaultSystemScopes = "udap",
                DefaultUserScopes = "udap",
                SsraaVersion = SsraaVersion.V1_1
            },
            configureServices: services =>
            {
                // Replace default validator with custom one BEFORE AddUdapServer registers it
                services.AddSingleton<IUdapAuthorizationExtensionValidator>(customValidator);
            });

#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var regResult = await RegisterClient(pipeline, clientCert);

        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError);
        Assert.Equal("custom_error", tokenResponse.Error);
        Assert.Equal("Custom validator rejected", tokenResponse.ErrorDescription);
    }

    [Fact]
    public async Task TokenRequest_TamperedJwt_Returns_InvalidClient_With_ErrorDescription()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1
        });

#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var regResult = await RegisterClient(pipeline, clientCert);

        // Build a valid token request, then tamper with the JWT signature
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        // Tamper with the signature to trigger JWT validation failure in UdapJwtSecretValidator
        var jwt = clientRequest.ClientAssertion.Value;
        var parts = jwt!.Split('.');
        var tamperedSignature = parts[2][..^2] + "XX"; // corrupt last 2 chars
        clientRequest.ClientAssertion.Value = $"{parts[0]}.{parts[1]}.{tamperedSignature}";

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.HttpStatusCode);
        Assert.Equal("invalid_client", tokenResponse.Error);
        Assert.NotNull(tokenResponse.ErrorDescription);
        Assert.Contains("Client assertion JWT validation failed", tokenResponse.ErrorDescription);
        _testOutputHelper.WriteLine($"error_description: {tokenResponse.ErrorDescription}");
    }

    #region Helpers

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
            Name = "udap://fhirlabs.net",
            Enabled = true,
            Default = true,
            Anchors =
            [
                new Anchor(sureFhirLabsAnchor, "udap://fhirlabs.net")
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

    private static async Task<UdapDynamicClientRegistrationDocument> RegisterClient(
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

    /// <summary>
    /// Simple community token validator for integration tests that provides rules
    /// via <see cref="ICommunityTokenValidator.GetValidationRules"/> and always
    /// returns success from <see cref="ICommunityTokenValidator.ValidateAsync"/>.
    /// </summary>
    private class TestCommunityTokenValidator : ICommunityTokenValidator
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
}
