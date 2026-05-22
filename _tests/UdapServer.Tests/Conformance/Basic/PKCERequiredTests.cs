#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using Duende.IdentityModel;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Conformance.Basic;

[Collection("Udap.Auth.Server")]
public class PKCERequiredTests
{
    private static readonly JsonSerializerOptions IndentedJsonOptions = new JsonSerializerOptions { WriteIndented = true };

    private readonly ITestOutputHelper _testOutputHelper;
    private readonly UdapAuthServerPipeline _mockPipeline = new UdapAuthServerPipeline();


    public PKCERequiredTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
#if NET9_0_OR_GREATER
        var sureFhirLabsAnchor = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#else
        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#endif

        _mockPipeline.OnPostConfigureServices += s =>
        {
            s.AddSingleton<ServerSettings>(new ServerSettings
            {
                DefaultUserScopes = "user/*.read",
                DefaultSystemScopes = "system/*.read",
                SsraaVersion = SsraaVersion.V2_0,
                RequireConsent = false
            });

            s.AddSingleton<UdapClientOptions>(new UdapClientOptions
            {
                ClientName = "Mock Client",
                Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" }
            });

        };

        _mockPipeline.OnPreConfigureServices += (_, s) =>
        {
            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // TODO: PR Deunde for this issue.
            // They register Clients as IEnumerable<Client> in AddInMemoryClients extension
            s.AddSingleton(_mockPipeline.Clients);

            s.AddScoped<IUdapClient>(sp =>
            {
                return new UdapClient(
                    _mockPipeline.BackChannelClient,
                    sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                    sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                    sp.GetRequiredService<ILogger<UdapClient>>());
            });
        };

        _mockPipeline.Initialize(enableLogging: true);
        _mockPipeline.BrowserClient.AllowAutoRedirect = false;

        _mockPipeline.Communities.Add(new Community
        {
            Name = "udap://fhirlabs.net",
            Enabled = true,
            Default = true,
            Anchors = [new Anchor(sureFhirLabsAnchor, "udap://fhirlabs.net")
            {
                BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                Name = sureFhirLabsAnchor.Subject,
                Enabled = true,
                Intermediates = new List<Intermediate>()
                {
                    new Intermediate(intermediateCert)
                    {
                        BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                        EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                        Name = intermediateCert.Subject,
                        Enabled = true
                    }
                }
            }]
        });

        _mockPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockPipeline.IdentityScopes.Add(new IdentityResources.Profile());

        _mockPipeline.ApiScopes.Add(new ApiScope("user/*.read"));
        _mockPipeline.ApiScopes.Add(new ApiScope("udap"));

        _mockPipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims =
            [
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
            ]
        });
    }

    [Fact]
    public async Task AuthorizeWithPKCSE_accepted()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .WithGrantType("refresh_token")
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;

        // Register
        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);

        var clientId = resultDocument!.ClientId;
        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();

        await _mockPipeline.LoginAsync("bob");
        var udapClient = _mockPipeline.Resolve<IUdapClient>();
        var pkce = udapClient.GeneratePkce();

        // Authorize
        var url = _mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument!.ClientId!,
            responseType: "code",
            scope: "openid offline_access",
            redirectUri: "https://code_client/callback",
            state: state,
            nonce: nonce,
            codeChallenge: pkce.CodeChallenge,
            codeChallengeMethod: OidcConstants.CodeChallengeMethods.Sha256);


        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await _mockPipeline.BrowserClient.GetAsync(url);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);

        Assert.NotNull(response.Headers.Location);
        Assert.Contains("https://code_client/callback", response.Headers.Location!.AbsoluteUri);
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Contains(queryParams, p => p.Key == "code");
        // Obsolete scope results in newer Duende builds during upgrade from 7.2.4 to 7.3.1
        // Assert.Equal("openid offline_access", queryParams.Single(q => q.Key == "scope").Value.ToString(), StringComparer.OrdinalIgnoreCase);
        Assert.Equal(state, queryParams.Single(q => q.Key == "state").Value.ToString(), StringComparer.OrdinalIgnoreCase);


        // Request Token From Auth Code
        var tokenRequest = AccessTokenRequestForAuthorizationCodeBuilder.Create(
                clientId,
                "https://server/connect/token",
                clientCert,
                "https://code_client/callback",
                queryParams.First(p => p.Key == "code").Value)
        .Build();

        tokenRequest.CodeVerifier = pkce.CodeVerifier;

        var tokenResponse = await udapClient.ExchangeCodeForTokenResponse(tokenRequest);

        Assert.NotNull(tokenResponse);
        Assert.NotNull(tokenResponse.IdentityToken);
        var jwt = new JwtSecurityToken(tokenResponse.IdentityToken);
        Assert.NotNull(new JwtSecurityToken(tokenResponse.AccessToken));

        using var jsonDocument = JsonDocument.Parse(jwt.Payload.SerializeToJson());
        var formattedStatement = JsonSerializer.Serialize(
            jsonDocument,
            IndentedJsonOptions
        );

        var formattedHeader = Base64UrlEncoder.Decode(jwt.EncodedHeader);

        _testOutputHelper.WriteLine(formattedHeader);
        _testOutputHelper.WriteLine(formattedStatement);


        // udap.org Tiered 4.3
        // aud: client_id of Resource Holder (matches client_id in Resource Holder request in Step 3.4)
        Assert.Contains(jwt.Claims, c => c.Type == "aud");
        Assert.Equal(clientId, jwt.Claims.Single(c => c.Type == "aud").Value);

        // iss: Auth Servers unique identifying URI 
        Assert.Contains(jwt.Claims, c => c.Type == "iss");
        Assert.Equal(UdapAuthServerPipeline.BaseUrl, jwt.Claims.Single(c => c.Type == "iss").Value);

    }


    [Fact]
    public async Task AuthorizeWithPKCSE_Missing_code_challenge()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .WithGrantType("refresh_token")
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;

        // Register
        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);

        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();

        await _mockPipeline.LoginAsync("bob");

        // Authorize
        var url = _mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument!.ClientId!,
            responseType: "code",
            scope: "openid offline_access",
            redirectUri: "https://code_client/callback",
            state: state,
            nonce: nonce,
            codeChallengeMethod: OidcConstants.CodeChallengeMethods.Sha256);
        
        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await _mockPipeline.BrowserClient.GetAsync(url);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var errorMessage = await response.Content.ReadFromJsonAsync<ErrorMessage>();
        Assert.NotNull(errorMessage);
        Assert.Equal("invalid_request", errorMessage!.Error); //defined in Duende
        Assert.Equal("code challenge required", errorMessage!.ErrorDescription, StringComparer.OrdinalIgnoreCase); //defined in Duende

    }


    [Fact]
    public async Task AuthorizeWithPKCSE_Invalid_code_verifier()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .WithGrantType("refresh_token")
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;

        // Register
        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.NotNull(resultDocument);
        Assert.NotNull(resultDocument!.ClientId);

        var clientId = resultDocument!.ClientId;
        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();

        await _mockPipeline.LoginAsync("bob");
        var udapClient = _mockPipeline.Resolve<IUdapClient>();
        var pkce = udapClient.GeneratePkce();

        // Authorize
        var url = _mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument!.ClientId!,
            responseType: "code",
            scope: "openid offline_access",
            redirectUri: "https://code_client/callback",
            state: state,
            nonce: nonce,
            codeChallenge: pkce.CodeChallenge,
            codeChallengeMethod: "S256");


        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await _mockPipeline.BrowserClient.GetAsync(url);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);

        Assert.NotNull(response.Headers.Location);
        Assert.Contains("https://code_client/callback", response.Headers.Location!.AbsoluteUri);
        //_testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Contains(queryParams, p => p.Key == "code");
        // Obsolete scope results in newer Duende builds during upgrade from 7.2.4 to 7.3.1
        // Assert.Equal("openid offline_access", queryParams.Single(q => q.Key == "scope").Value.ToString(), StringComparer.OrdinalIgnoreCase);
        Assert.Equal(state, queryParams.Single(q => q.Key == "state").Value.ToString(), StringComparer.OrdinalIgnoreCase);


        // Request Token From Auth Code
        var tokenRequest = AccessTokenRequestForAuthorizationCodeBuilder.Create(
                clientId,
                "https://server/connect/token",
                clientCert,
                "https://code_client/callback",
                queryParams.First(p => p.Key == "code").Value)
        .Build();

        tokenRequest.CodeVerifier = "bad_guy";

        var tokenResponse = await udapClient.ExchangeCodeForTokenResponse(tokenRequest);

        Assert.NotNull(tokenResponse);
        Assert.True(tokenResponse.IsError);
        Assert.Null(tokenResponse.IdentityToken);
        Assert.Null(tokenResponse.AccessToken);

        Assert.Equal("invalid_grant", tokenResponse.Error);

        //
        // a second valid code_verifier should just fail for invalid_grant
        // because it was already attempted and the session was tossed out.
        //

        tokenRequest.CodeVerifier = pkce.CodeVerifier;
        tokenResponse = await udapClient.ExchangeCodeForTokenResponse(tokenRequest);
        Assert.True(tokenResponse.IsError);
        Assert.NotNull(tokenResponse);
        Assert.True(tokenResponse.IsError);
        Assert.Null(tokenResponse.IdentityToken);
        Assert.Null(tokenResponse.AccessToken);

        Assert.Equal("invalid_grant", tokenResponse.Error);
    }
}
