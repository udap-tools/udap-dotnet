using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using FluentAssertions;
using IdentityModel.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Udap.Client.Configuration;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Server.Configuration;
using Udap.Util.Extensions;
using UdapServer.Tests.Common;
using Xunit.Abstractions;
using Yarp.ReverseProxy.Configuration;

namespace UdapServer.Tests.Conformance.Tiered;

[Collection("Udap.Idp")]
public class TieredOauthTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    private UdapIdentityServerPipeline _mockAuthorServerPipeline = new UdapIdentityServerPipeline();
    private UdapIdentityServerPipeline _mockIdentityProviderPipeline = new UdapIdentityServerPipeline();

    public TieredOauthTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");

        BuildUdapAuthorizationServer(sureFhirLabsAnchor, intermediateCert);
        BuildUdapIdentityProvider(sureFhirLabsAnchor, intermediateCert);
    }

    private void BuildUdapAuthorizationServer(X509Certificate2 sureFhirLabsAnchor, X509Certificate2 intermediateCert)
    {
        _mockAuthorServerPipeline.OnPostConfigureServices += s =>
        {
            s.AddSingleton<ServerSettings>(new ServerSettings
            {
                ServerSupport = ServerSupport.UDAP,
                DefaultUserScopes = "udap",
                DefaultSystemScopes = "udap"
                // ForceStateParamOnAuthorizationCode = false (default)
            });

            s.AddSingleton<UdapClientOptions>(new UdapClientOptions
            {
                ClientName = "Mock Client",
                Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" }
            });


        };

        _mockAuthorServerPipeline.OnPreConfigureServices += services =>
        {
            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // Duende's AddInMemoryClients extension registers as IEnumerable<Client> and is used in InMemoryClientStore as readonly.
            // It was not intended to work with the concept of a dynamic client registration.
            services.AddSingleton(_mockAuthorServerPipeline.Clients);

            // services.AddReverseProxy()
            //     .LoadFromMemory(
            //         new[]
            //         {
            //             new RouteConfig()
            //             {
            //                 RouteId = "api_user",
            //                 ClusterId = "cluster1",
            //
            //                 Match = new()
            //                 {
            //                     Path = "/server/connect/authorize"
            //                 }
            //             }
            //         },
            //         new[]
            //         {
            //             new ClusterConfig
            //             {
            //                 ClusterId = "cluster1",
            //
            //                 Destinations = new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase)
            //                 {
            //                     { "destination1", new() { Address = "https://localhost:5010" } },
            //                 }
            //             }
            //         });
        };

        // _mockAuthorServerPipeline.OnPostConfigure += app =>
        // {
        //     // Enable endpoint routing, required for the reverse proxy
        //     app.UseRouting();
        //     // Register the reverse proxy routes
        //     app.UseEndpoints(endpoints =>
        //     {
        //         endpoints.MapReverseProxy();
        //     });
        // };

        _mockAuthorServerPipeline.Initialize(enableLogging: true);
        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = false;

        _mockAuthorServerPipeline.Communities.Add(new Community
        {
            Name = "udap://fhirlabs.net",
            Enabled = true,
            Default = true,
            Anchors = new[]
            {
                new Anchor
                {
                    BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                    EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                    Name = sureFhirLabsAnchor.Subject,
                    Community = "udap://fhirlabs.net",
                    Certificate = sureFhirLabsAnchor.ToPemFormat(),
                    Thumbprint = sureFhirLabsAnchor.Thumbprint,
                    Enabled = true,
                    Intermediates = new List<Intermediate>()
                    {
                        new Intermediate
                        {
                            BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                            Name = intermediateCert.Subject,
                            Certificate = intermediateCert.ToPemFormat(),
                            Thumbprint = intermediateCert.Thumbprint,
                            Enabled = true
                        }
                    }
                }
            }
        });

        _mockAuthorServerPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockAuthorServerPipeline.IdentityScopes.Add(new IdentityResources.Profile());

        _mockAuthorServerPipeline.ApiScopes.Add(new ApiScope("user/*.read"));
        _mockAuthorServerPipeline.ApiScopes.Add(new ApiScope("udap"));

        _mockAuthorServerPipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims = new Claim[]
            {
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
            }
        });
    }

    private void BuildUdapIdentityProvider(X509Certificate2 sureFhirLabsAnchor, X509Certificate2 intermediateCert)
    {
        _mockIdentityProviderPipeline.OnPostConfigureServices += s =>
        {
            s.AddSingleton<ServerSettings>(new ServerSettings
            {
                ServerSupport = ServerSupport.UDAP,
                DefaultUserScopes = "udap",
                DefaultSystemScopes = "udap"
                // ForceStateParamOnAuthorizationCode = false (default)
            });

            s.AddSingleton<UdapClientOptions>(new UdapClientOptions
            {
                ClientName = "Mock Client",
                Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" }
            });

        };

        _mockIdentityProviderPipeline.OnPreConfigureServices += s =>
        {
            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // Duende's AddInMemoryClients extension registers as IEnumerable<Client> and is used in InMemoryClientStore as readonly.
            // It was not intended to work with the concept of a dynamic client registration.
            s.AddSingleton(_mockIdentityProviderPipeline.Clients);
        };

        _mockIdentityProviderPipeline.Initialize(enableLogging: true);
        _mockIdentityProviderPipeline.BrowserClient.AllowAutoRedirect = false;

        _mockIdentityProviderPipeline.Communities.Add(new Community
        {
            Name = "udap://fhirlabs.net",
            Enabled = true,
            Default = true,
            Anchors = new[]
            {
                new Anchor
                {
                    BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                    EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                    Name = sureFhirLabsAnchor.Subject,
                    Community = "udap://fhirlabs.net",
                    Certificate = sureFhirLabsAnchor.ToPemFormat(),
                    Thumbprint = sureFhirLabsAnchor.Thumbprint,
                    Enabled = true,
                    Intermediates = new List<Intermediate>()
                    {
                        new Intermediate
                        {
                            BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                            Name = intermediateCert.Subject,
                            Certificate = intermediateCert.ToPemFormat(),
                            Thumbprint = intermediateCert.Thumbprint,
                            Enabled = true
                        }
                    }
                }
            }
        });

        _mockIdentityProviderPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockIdentityProviderPipeline.IdentityScopes.Add(new IdentityResources.Profile());

        _mockIdentityProviderPipeline.ApiScopes.Add(new ApiScope("user/*.read"));
        _mockIdentityProviderPipeline.ApiScopes.Add(new ApiScope("udap"));

        _mockIdentityProviderPipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims = new Claim[]
            {
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
            }
        });
    }

    [Fact]
    public async Task ShouldReturnAuthorizationCode()
    {
        // Register client with auth server
        var resultDocument = await RegisterClientWithAuthServer();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        // Data Holder's Auth Server validates Identity Provider's Auth Server software statement

        var state = Guid.NewGuid().ToString();

        var url = _mockAuthorServerPipeline.CreateAuthorizeUrl(
            clientId: resultDocument!.ClientId!,
            responseType: "code",
            scope: "udap",
            redirectUri: "https://code_client/callback",
            state: state,
            extra: new { name = UdapConstants.AuthorizeRequestExtra.Idp, value = "https://idp.example.com/optionalpath" });

        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = false;
        var response = await _mockAuthorServerPipeline.BrowserClient.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync());

        response.Headers.Location.Should().NotBeNull();
        response.Headers.Location!.AbsoluteUri.Should().Contain("https://code_client/callback");
        _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        queryParams.Should().Contain(p => p.Key == "code");
        queryParams.Single(q => q.Key == "scope").Value.Should().BeEquivalentTo("udap");
        queryParams.Single(q => q.Key == "state").Value.Should().BeEquivalentTo(state);

    }

    private async Task<UdapDynamicClientRegistrationDocument?> RegisterClientWithAuthServer()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        await _mockAuthorServerPipeline.LoginAsync("bob");

        var document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock tiered test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("udap")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .Build();


        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        _mockAuthorServerPipeline.BrowserClient.AllowAutoRedirect = true;

        var response = await _mockAuthorServerPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        return resultDocument;
    }
}
