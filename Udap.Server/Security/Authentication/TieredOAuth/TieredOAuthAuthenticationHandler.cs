#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics.CodeAnalysis;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Web;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Udap.Client.Client;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Server.Storage.Stores;
using Udap.Util.Extensions;

namespace Udap.Server.Security.Authentication.TieredOAuth;

public class TieredOAuthAuthenticationHandler : OAuthHandler<TieredOAuthAuthenticationOptions>
{
    private readonly IUdapClient _udapClient;
    private readonly IPrivateCertificateStore _certificateStore;
    private readonly IServiceScopeFactory _scopeFactory;

    /// <summary>
    /// Initializes a new instance of <see cref="TieredOAuthHandler" />.
    /// </summary>
    /// <inheritdoc />
    public TieredOAuthAuthenticationHandler(
        IOptionsMonitor<TieredOAuthAuthenticationOptions> options,
        ILoggerFactory logger, 
        UrlEncoder encoder, 
        ISystemClock clock,
        IUdapClient udapClient,
        IPrivateCertificateStore certificateStore,
        IServiceScopeFactory scopeFactory) :
        base(options, logger, encoder, clock)
    {
        _udapClient = udapClient;
        _certificateStore = certificateStore;
        _scopeFactory = scopeFactory;
    }

    /// <summary>Constructs the OAuth challenge url.</summary>
    /// <param name="properties">The <see cref="T:Microsoft.AspNetCore.Authentication.AuthenticationProperties" />.</param>
    /// <param name="redirectUri">The url to redirect to once the challenge is completed.</param>
    /// <returns>The challenge url.</returns>
    protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
    {
        var queryStrings = new Dictionary<string, string>
        {
            { "response_type", "code" },
            { "redirect_uri", redirectUri }
        };

        AddQueryString(queryStrings, properties, "client_id");
        AddQueryString(queryStrings, properties, OAuthChallengeProperties.ScopeKey, FormatScope, Options.Scope);

        var state = Options.StateDataFormat.Protect(properties);
        queryStrings.Add("state", state);
        var authorizationEndpoint = QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, queryStrings!);
        
        return authorizationEndpoint;
        
    }

    public string BuildUrl(AuthenticationProperties properties, string redirectUri)
    {
        if(properties.Parameters.TryGetValue("client_id", out var clientId))
        {
            Options.ClientId = (clientId as string)!;
        }
        return base.BuildChallengeUrl(properties, redirectUri);
    }

    /// <summary>
    /// Called after options/events have been initialized for the handler to finish initializing itself.
    /// </summary>
    /// <returns>A task</returns>
    protected override Task InitializeHandlerAsync()
    {

        return base.InitializeHandlerAsync();
    }


    /// <inheritdoc />
    protected override async Task<OAuthTokenResponse> ExchangeCodeAsync([NotNull] OAuthCodeExchangeContext context)
    {
        Logger.LogInformation("UDAP exchanging authorization code.");
        Logger.LogDebug(context.Properties.Items["returnUrl"]);
        Logger.LogDebug(Context.Request.QueryString.Value);

        var originalRequestParams = HttpUtility.ParseQueryString(context.Properties.Items["returnUrl"]);
        var idp = (originalRequestParams.GetValues("idp") ?? throw new InvalidOperationException()).Last();
        // var redirectUrl = originalRequestParams.Get("redirect_uri");
        var resourceHolderRedirectUrl =
            $"{Context.Request.Scheme}://{Context.Request.Host}{Context.Request.PathBase}{TieredOAuthAuthenticationDefaults.CallbackPath}";

        var requestParams = Context.Request.Query;
        var code = requestParams["code"];

        using var serviceScope = _scopeFactory.CreateScope();
        var clientStore = serviceScope.ServiceProvider.GetRequiredService<IClientStore>();
        var idpClient = await clientStore.FindClientByIdAsync(idp);
        var idpClientId = idpClient.ClientSecrets
            .Single(cs => cs.Type == "TIERED_OAUTH_CLIENT_ID")?.Value;

        await _certificateStore.Resolve();

        // Sign request for token 
        var tokenRequestBuilder = AccessTokenRequestForAuthorizationCodeBuilder.Create(
            idpClientId,
            Options.TokenEndpoint,
            _certificateStore.IssuedCertificates.Where(ic => ic.IdPBaseUrl == idp)
                //TODO: multiple certs or latest cert?
                .Select(ic => ic.Certificate).First(),
            resourceHolderRedirectUrl,
            code);

        //TODO algorithm selectable.
        var tokenRequest = tokenRequestBuilder.Build();
        
        return await _udapClient.ExchangeCode(tokenRequest, Context.RequestAborted);
    }

    /// <inheritdoc />
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var requestParams = HttpUtility.ParseQueryString(properties.Items["returnUrl"]);
        
        var idp = (requestParams.GetValues("idp") ?? throw new InvalidOperationException()).Last();
        var scope = (requestParams.GetValues("scope") ?? throw new InvalidOperationException()).First();
        var clientRedirectUrl = (requestParams.GetValues("redirect_uri") ?? throw new InvalidOperationException()).Last();
        var updateRegistration = requestParams.GetValues("update_registration").Last();

        // Validate idp Server;
        var community = idp.GetCommunityFromQueryParams();
        var response = await _udapClient.ValidateResource(idp, community);
        var resourceHolderRedirectUrl =
            $"{Context.Request.Scheme}://{Context.Request.Host}{Context.Request.PathBase}{TieredOAuthAuthenticationDefaults.CallbackPath}";

        if (response.IsError)
        {
            Logger.LogError(response.Error);

            await HandleForbiddenAsync(properties);
        }
        else
        {
            Logger.LogInformation($"Validated UDAP signed_metadata from {idp}");
            Logger.LogDebug(JsonSerializer.Serialize(
                _udapClient.UdapServerMetaData,
                new JsonSerializerOptions { WriteIndented = true }));
        }

        //
        // if not registered with IdP, then register.
        //

        using var serviceScope = _scopeFactory.CreateScope();
        var clientStore = serviceScope.ServiceProvider.GetRequiredService<IClientStore>();
        var idpClient = await clientStore.FindClientByIdAsync(idp);

        var idpClientId = null as string;

        if (idpClient != null)
        {
            idpClientId = idpClient.ClientSecrets
                .SingleOrDefault(cs => cs.Type == "TIERED_OAUTH_CLIENT_ID")?.Value;
        }

        // TODO Special provision query param updateRegistration to enable update registration.
        // Not sure if it stays here or lives in an Admin tool.
        if (idpClient == null || !idpClient.Enabled || updateRegistration == "true")
        {
            await _certificateStore.Resolve();


            var communityName = _certificateStore.IssuedCertificates.First().Community;
            var registrationStore = serviceScope.ServiceProvider.GetRequiredService<IUdapClientRegistrationStore>();
            
            var communityId =
                await registrationStore.GetCommunityId(communityName, Context.RequestAborted);

            if (communityId == null)
            {
                Logger.LogInformation(
                    "Tiered Oauth: Cannot find communityId for community: {communityName}",
                    communityName);
                //Todo: return strategy?
                return;
            }

            //TODO: RegisterClient should be typed to the two builders
            // UdapDcrBuilderForAuthorizationCode or UdapDcrBuilderForClientCredentials
            var document = await _udapClient.RegisterClient(
                resourceHolderRedirectUrl,
                _certificateStore.IssuedCertificates.Where(ic => ic.IdPBaseUrl == idp)
                    .Select(ic => ic.Certificate), 
                Context.RequestAborted);

            idpClientId = idpClient.ClientSecrets
                .SingleOrDefault(cs => cs.Type == "TIERED_OAUTH_CLIENT_ID")?.Value;

            var tokenHandler = new JsonWebTokenHandler();
            var jsonWebToken = tokenHandler.ReadJsonWebToken(document.SoftwareStatement);
            var publicCert = jsonWebToken.GetPublicCertificate();
            

            var client = new Duende.IdentityServer.Models.Client
            {
                ClientId = idp,
                ClientName = document.ClientName,
            };

            var clientSecrets = client.ClientSecrets = new List<Duende.IdentityServer.Models.Secret>();

            clientSecrets.Add(new()
            {
                Expiration = publicCert.NotAfter,
                Type = UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME,
                Value = idp
            });

            clientSecrets.Add(new()
            {
                Expiration = publicCert.NotAfter,
                Type = UdapServerConstants.SecretTypes.UDAP_COMMUNITY,
                Value = communityId
            });

            //TODO: Temp solution.  Need to create first class UdapTieredOAuthClient entity instead
            clientSecrets.Add(new()
            {
                Expiration = publicCert.NotAfter,
                Type = "TIERED_OAUTH_CLIENT_ID",
                Value = document.ClientId
            });

            client.AllowedGrantTypes.Add(GrantType.AuthorizationCode);

            if (document.GrantTypes != null &&
                document.GrantTypes.Contains(OidcConstants.GrantTypes.RefreshToken))
            {
                if (client.AllowedGrantTypes.Count == 1 &&
                    client.AllowedGrantTypes.FirstOrDefault(t =>
                        t.Equals(GrantType.ClientCredentials)) != null)
                {
                    // TODO: Technique in UdapClientRegistrationValidator.ValidateClientSecretsAsync
                    // return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    //     UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    //     "client credentials does not support refresh tokens"));

                    Context.Response.StatusCode = StatusCodes.Status400BadRequest;

                    var error = new UdapDynamicClientRegistrationErrorResponse
                    (
                        UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                        UdapDynamicClientRegistrationErrorDescriptions
                            .ClientCredentialsRefreshError
                    );
                    Logger.LogWarning(JsonSerializer.Serialize(error));

                    await Context.Response.WriteAsJsonAsync(error,
                        cancellationToken: Context.RequestAborted);

                    return;
                }

                client.AllowOfflineAccess = true;
            }


            //
            // validate redirect URIs and ResponseTypes, add redirect_url
            //
            if (client.AllowedGrantTypes.Contains(GrantType.AuthorizationCode))
            {
                if (document.RedirectUris != null && document.RedirectUris.Any())
                {
                    foreach (var requestRedirectUri in document.RedirectUris)
                    {
                        //TODO add tests and decide how to handle invalid Uri exception
                        var uri = new Uri(requestRedirectUri);

                        if (uri.IsAbsoluteUri)
                        {
                            client.RedirectUris.Add(uri.OriginalString);
                            //TODO: I need to create a policy engine or dig into the Duende policy stuff and see it if makes sense
                            //Threat analysis?
                            client.RequirePkce = false;
                            client.AllowOfflineAccess = true;
                        }
                        else
                        {
                            var error = new UdapDynamicClientRegistrationErrorResponse
                            (
                                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                                UdapDynamicClientRegistrationErrorDescriptions
                                    .MalformedRedirectUri
                            );

                            await Context.Response.WriteAsJsonAsync(error,
                                cancellationToken: Context.RequestAborted);

                            return;
                        }
                    }
                }
                else
                {
                    var error = new UdapDynamicClientRegistrationErrorResponse
                    (
                        UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                        UdapDynamicClientRegistrationErrorDescriptions
                            .RedirectUriRequiredForAuthCode
                    );

                    await Context.Response.WriteAsJsonAsync(error,
                        cancellationToken: Context.RequestAborted);

                    return;
                }

                if (document.ResponseTypes != null && document.ResponseTypes.Count == 0)
                {
                    Logger.LogWarning(
                        $"{UdapDynamicClientRegistrationErrors.InvalidClientMetadata}::" +
                        UdapDynamicClientRegistrationErrorDescriptions.ResponseTypesMissing);

                    var error = new UdapDynamicClientRegistrationErrorResponse
                    (
                        UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                        UdapDynamicClientRegistrationErrorDescriptions.ResponseTypesMissing
                    );

                    await Context.Response.WriteAsJsonAsync(error,
                        cancellationToken: Context.RequestAborted);

                    return;
                }
            }

            await registrationStore.UpsertClient(client, Context.RequestAborted);
        }

        properties.SetParameter("client_id", idpClientId);

        await base.HandleChallengeAsync(properties);
    }


    private static void AddQueryString<T>(
        IDictionary<string, string> queryStrings,
        AuthenticationProperties properties,
        string name,
        Func<T, string?> formatter,
        T defaultValue)
    {
        string? value;
        var parameterValue = properties.GetParameter<T>(name);
        if (parameterValue != null)
        {
            value = formatter(parameterValue);
        }
        else if (!properties.Items.TryGetValue(name, out value))
        {
            value = formatter(defaultValue);
        }

        // Remove the parameter from AuthenticationProperties so it won't be serialized into the state
        properties.Items.Remove(name);

        if (value != null)
        {
            queryStrings[name] = value;
        }
    }

    private static void AddQueryString(
        IDictionary<string, string> queryStrings,
        AuthenticationProperties properties,
        string name,
        string? defaultValue = null)
        => AddQueryString(queryStrings, properties, name, x => x, defaultValue);
}