#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Web;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Client;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Server.Storage.Stores;
using Udap.Util.Extensions;
using static IdentityModel.ClaimComparer;

namespace Udap.Server.Security.Authentication.TieredOAuth;


public class TieredOAuthAuthenticationHandler : OAuthHandler<TieredOAuthAuthenticationOptions>
{
    private readonly IUdapClient _udapClient;
    private readonly IPrivateCertificateStore _certificateStore;
    private readonly IUdapClientRegistrationStore _udapClientRegistrationStore;

    /// <summary>
    /// Initializes a new instance of <see cref="TieredOAuthAuthenticationHandler" />.
    /// </summary>
    /// <inheritdoc />
    public TieredOAuthAuthenticationHandler(
        IOptionsMonitor<TieredOAuthAuthenticationOptions> options,
        ILoggerFactory logger, 
        UrlEncoder encoder, 
        ISystemClock clock,
        IUdapClient udapClient,
        IPrivateCertificateStore certificateStore,
        IUdapClientRegistrationStore udapClientRegistrationStore,
        IEnumerable<IdentityProvider> identityProviders
        ) :
        base(options, logger, encoder, clock)
    {
        _udapClient = udapClient;
        _certificateStore = certificateStore;
        _udapClientRegistrationStore = udapClientRegistrationStore;
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

        AddQueryString(queryStrings, properties, "client_id", true);
        AddQueryString(queryStrings, properties, OAuthChallengeProperties.ScopeKey, FormatScope, Options.Scope);

        var state = Options.StateDataFormat.Protect(properties);
        queryStrings.Add("state", state);

        // Static configured Options
        // if (!Options.AuthorizationEndpoint.IsNullOrEmpty())
        // {
        //     return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, queryStrings!);
        // }

        var authEndpoint = properties.Parameters[UdapConstants.Discovery.AuthorizationEndpoint] as string ??
                           throw new InvalidOperationException("Missing IdP authorization endpoint.");

        var community = properties.GetParameter<string>(UdapConstants.Community);
        
        if (!community.IsNullOrEmpty())
        {
            queryStrings.Add(UdapConstants.Community, community!);
        }

        var tokenEndpoint = properties.GetParameter<string>(UdapConstants.Discovery.TokenEndpoint);

        if (!tokenEndpoint.IsNullOrEmpty())
        {
            Options.TokenEndpoint = tokenEndpoint!;
        } 

        var idpBaseUrl = properties.GetParameter<string>("idpBaseUrl");

        if (!idpBaseUrl.IsNullOrEmpty())
        {
            Options.IdPBaseUrl = idpBaseUrl;
        }

        // Dynamic options
        return QueryHelpers.AddQueryString(authEndpoint, queryStrings!);
    }
    

    /// <summary>
    /// Called after options/events have been initialized for the handler to finish initializing itself.
    /// </summary>
    /// <returns>A task</returns>
    protected override Task InitializeHandlerAsync()
    {

        return base.InitializeHandlerAsync();
    }

    //
    // TODO: come back here and decide if this was the way to go.
    // Code from base Microsoft.AspNetCore.Authentication.OAuth.OAuthHandler.
    // Modified to behave according to UDAP Tiered OAuth // I am considering going
    // implementing OpenIdConnectHandler.HandleRemoteAuthenticateAsync internals instead.
    // Or start over and use OpenIdConnectHandler.  Maybe not inherit from it, but connect up the DCR and PKI
    // mechanics via OpenIdConnectEvents, like hook events via
    // options.Events.OnAuthorizationCodeReceived = RedeemAuthorizationCodeAsync;
    // from within the OpenIdConnectHandler.HandleRemoteAuthenticateAsync method
    // https://github.com/dotnet/aspnetcore/issues/10564
    // 

    /// <inheritdoc />
    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        var query = Request.Query;

        try
        {
            var state = query["state"];
            var properties = Options.StateDataFormat.Unprotect(state);

            if (properties == null)
            {
                return HandleRequestResults.InvalidState;
            }

            // OAuth2 10.12 CSRF
            // https://datatracker.ietf.org/doc/html/rfc6749#section-10.12
            if (!ValidateCorrelationId(properties))
            {
                return HandleRequestResult.Fail("Correlation failed.", properties);
            }

            var error = query["error"];
            if (!StringValues.IsNullOrEmpty(error))
            {
                // Note: access_denied errors are special protocol errors indicating the user didn't
                // approve the authorization demand requested by the remote authorization server.
                // Since it's a frequent scenario (that is not caused by incorrect configuration),
                // denied errors are handled differently using HandleAccessDeniedErrorAsync().
                // Visit https://tools.ietf.org/html/rfc6749#section-4.1.2.1 for more information.
                var errorDescription = query["error_description"];
                var errorUri = query["error_uri"];
                if (StringValues.Equals(error, "access_denied"))
                {
                    var result = await HandleAccessDeniedErrorAsync(properties);
                    if (!result.None)
                    {
                        return result;
                    }

                    var deniedEx = new Exception("Access was denied by the resource owner or by the remote server.");
                    deniedEx.Data["error"] = error.ToString();
                    deniedEx.Data["error_description"] = errorDescription.ToString();
                    deniedEx.Data["error_uri"] = errorUri.ToString();

                    return HandleRequestResult.Fail(deniedEx, properties);
                }

                var failureMessage = new StringBuilder();
                failureMessage.Append(error);
                if (!StringValues.IsNullOrEmpty(errorDescription))
                {
                    failureMessage.Append(";Description=").Append(errorDescription);
                }

                if (!StringValues.IsNullOrEmpty(errorUri))
                {
                    failureMessage.Append(";Uri=").Append(errorUri);
                }

                var ex = new Exception(failureMessage.ToString());
                ex.Data["error"] = error.ToString();
                ex.Data["error_description"] = errorDescription.ToString();
                ex.Data["error_uri"] = errorUri.ToString();

                return HandleRequestResult.Fail(ex, properties);
            }

            var code = query["code"];

            if (StringValues.IsNullOrEmpty(code))
            {
                return HandleRequestResult.Fail("Code was not found.", properties);
            }


            JwtSecurityToken? jwt = null;
            string? nonce = null;
            //
            // Options.ProtocolValidator.ValidateAuthenticationResponse(new OpenIdConnectProtocolValidationContext()
            // {
            //     ClientId = Options.ClientId,
            //     ProtocolMessage = authorizationResponse,
            //     ValidatedIdToken = jwt,
            //     Nonce = nonce
            // });


            var codeExchangeContext =
                new OAuthCodeExchangeContext(properties, code.ToString(), BuildRedirectUri(Options.CallbackPath));

            // UDAP
            using var tokens = await ExchangeCodeAsync(codeExchangeContext);

            if (tokens.Error != null)
            {
                return HandleRequestResult.Fail(tokens.Error, properties);
            }

            if (string.IsNullOrEmpty(tokens.AccessToken))
            {
                return HandleRequestResult.Fail("Failed to retrieve access token.", properties);
            }

            var idToken = tokens.Response?.RootElement.GetString("id_token");
            
            if (idToken == null)
            {
                return HandleRequestResults.MissingIdToken;
            }

            var validationParameters = Options.TokenValidationParameters.Clone();

            // TODO: pre installed keys check?

            var request = new DiscoveryDocumentRequest
            {
                Address = Options.IdPBaseUrl,
                Policy = new IdentityModel.Client.DiscoveryPolicy()
                {
                    //TODO: Promote to TieredOAuthOptions.  Maybe even injectable for advanced use cases.
                    EndpointValidationExcludeList = new List<string>{ OidcConstants.Discovery.RegistrationEndpoint }
                }
            };

            var keys = await _udapClient.ResolveJwtKeys(request);
            validationParameters.IssuerSigningKeys = keys;

            var tokenEndpointUser = ValidateToken(idToken, properties, validationParameters, out var tokenEndpointJwt);

            // nonce = tokenEndpointJwt.Payload.Nonce;
            // if (!string.IsNullOrEmpty(nonce))
            // {
            //     nonce = ReadNonceCookie(nonce);
            // }

            // var tokenValidatedContext = await RunTokenValidatedEventAsync(authorizationResponse, tokenEndpointResponse, tokenEndpointUser, properties, tokenEndpointJwt, nonce);
            // if (tokenValidatedContext.Result != null)
            // {
            //     return tokenValidatedContext.Result;
            // }
            // authorizationResponse = tokenValidatedContext.ProtocolMessage;
            // tokenEndpointResponse = tokenValidatedContext.TokenEndpointResponse;
            // user = tokenValidatedContext.Principal!;
            // properties = tokenValidatedContext.Properties;
            // jwt = tokenValidatedContext.SecurityToken;
            // nonce = tokenValidatedContext.Nonce;


            return HandleRequestResult.Success(new AuthenticationTicket(tokenEndpointUser, properties, Scheme.Name));
        }
        catch (Exception exception)
        {
            return HandleRequestResult.Fail(exception);
        }
    }

    // Note this modifies properties if Options.UseTokenLifetime
    private ClaimsPrincipal ValidateToken(
        string idToken, 
        AuthenticationProperties properties, 
        TokenValidationParameters validationParameters,
        out JwtSecurityToken jwt)
    {
        if (!Options.SecurityTokenValidator.CanReadToken(idToken))
        {
            // Logger.UnableToReadIdToken(idToken);
            throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, "Unable to validate the 'id_token', no suitable ISecurityTokenValidator was found for: '{0}'.\"", idToken));
        }

        // if (_configuration != null)
        // {
        //     var issuer = new[] { _configuration.Issuer };
        //     validationParameters.ValidIssuers = validationParameters.ValidIssuers?.Concat(issuer) ?? issuer;
        //
        //     validationParameters.IssuerSigningKeys = validationParameters.IssuerSigningKeys?.Concat(_configuration.SigningKeys)
        //         ?? _configuration.SigningKeys;
        // }

        // no need to validate signature when token is received using "code flow" as per spec
        // [http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation].
        validationParameters.ValidIssuer = Options.IdPBaseUrl;
        properties.Items.TryGetValue("client_id", out var clientId);
        validationParameters.ValidAudience = clientId;
        validationParameters.ValidateIssuerSigningKey = false;
        
        var principal = Options.SecurityTokenValidator.ValidateToken(idToken, validationParameters, out SecurityToken validatedToken);
        if (validatedToken is JwtSecurityToken validatedJwt)
        {
            jwt = validatedJwt;
        }
        else
        {
            // Logger.InvalidSecurityTokenType(validatedToken?.GetType().ToString());
            throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, "The Validated Security Token must be of type JwtSecurityToken, but instead its type is: '{0}'.", validatedToken?.GetType()));
        }

        if (validatedToken == null)
        {
            // Logger.UnableToValidateIdToken(idToken);
            throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, "Unable to validate the 'id_token', no suitable ISecurityTokenValidator was found for: '{0}'.", idToken));
        }

        // if (Options.UseTokenLifetime)
        // {
        //     var issued = validatedToken.ValidFrom;
        //     if (issued != DateTime.MinValue)
        //     {
        //         properties.IssuedUtc = issued;
        //     }
        //
        //     var expires = validatedToken.ValidTo;
        //     if (expires != DateTime.MinValue)
        //     {
        //         properties.ExpiresUtc = expires;
        //     }
        // }

        return principal;
    }

    /// <summary>
    /// Searches <see cref="HttpRequest.Cookies"/> for a matching nonce.
    /// </summary>
    /// <param name="nonce">the nonce that we are looking for.</param>
    /// <returns>echos 'nonce' if a cookie is found that matches, null otherwise.</returns>
    /// <remarks>Examine <see cref="IRequestCookieCollection.Keys"/> of <see cref="HttpRequest.Cookies"/> that start with the prefix: 'OpenIdConnectAuthenticationDefaults.Nonce'.
    /// <see cref="M:ISecureDataFormat{TData}.Unprotect"/> of <see cref="OpenIdConnectOptions.StringDataFormat"/> is used to obtain the actual 'nonce'. If the nonce is found, then <see cref="M:IResponseCookies.Delete"/> of <see cref="HttpResponse.Cookies"/> is called.</remarks>
    // private string? ReadNonceCookie(string nonce)
    // {
    //     if (nonce == null)
    //     {
    //         return null;
    //     }
    //
    //     foreach (var nonceKey in Request.Cookies.Keys)
    //     {
    //         if (Options.NonceCookie.Name is string name && nonceKey.StartsWith(name, StringComparison.Ordinal))
    //         {
    //             try
    //             {
    //                 var nonceDecodedValue = Options.StringDataFormat.Unprotect(nonceKey.Substring(Options.NonceCookie.Name.Length, nonceKey.Length - Options.NonceCookie.Name.Length));
    //                 if (nonceDecodedValue == nonce)
    //                 {
    //                     var cookieOptions = Options.NonceCookie.Build(Context, Clock.UtcNow);
    //                     Response.Cookies.Delete(nonceKey, cookieOptions);
    //                     return nonce;
    //                 }
    //             }
    //             catch (Exception ex)
    //             {
    //                 Logger.UnableToProtectNonceCookie(ex);
    //             }
    //         }
    //     }
    //
    //     return null;
    // }

    /// <inheritdoc />
    protected override async Task<OAuthTokenResponse> ExchangeCodeAsync([NotNull] OAuthCodeExchangeContext context)
    {
        Logger.LogInformation("UDAP exchanging authorization code.");
        Logger.LogDebug(context.Properties.Items["returnUrl"] ?? "~/");
        Logger.LogDebug(Context.Request.QueryString.Value);

        var originalRequestParams = HttpUtility.ParseQueryString(context.Properties.Items["returnUrl"] ?? "~/");
        var idp = (originalRequestParams.GetValues("idp") ?? throw new InvalidOperationException()).Last();
        var idpUri = new Uri(idp);
        var communityParam = (HttpUtility.ParseQueryString(idpUri.Query).GetValues("community") ?? Array.Empty<string>()).LastOrDefault();

        var clientId = context.Properties.Items["client_id"];
        
        var resourceHolderRedirectUrl =
            $"{Context.Request.Scheme}{Uri.SchemeDelimiter}{Context.Request.Host}{Context.Request.PathBase}{Options.CallbackPath}";

        var requestParams = Context.Request.Query;
        var code = requestParams["code"];
        var idpClient = await _udapClientRegistrationStore.FindTieredClientById(clientId);
        var idpClientId = idpClient.ClientId;

        await _certificateStore.Resolve();

        // Sign request for token 
        var tokenRequestBuilder = AccessTokenRequestForAuthorizationCodeBuilder.Create(
            idpClientId,
            Options.TokenEndpoint,

            communityParam == null
                ?
                _certificateStore.IssuedCertificates.First().Certificate
                :
                _certificateStore.IssuedCertificates.Where(ic => ic.Community == communityParam)
                //TODO: multiple certs or latest cert?
                    .Select(ic => ic.Certificate).First(),
            
            resourceHolderRedirectUrl,
            code);

        //TODO algorithm selectable.
        var tokenRequest = tokenRequestBuilder.Build();
        
        return await _udapClient.ExchangeCodeForAuthTokenResponse(tokenRequest, Context.RequestAborted);
    }

    /// <inheritdoc />
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var requestParams = HttpUtility.ParseQueryString(properties.Items["returnUrl"] ?? "~/");
        
        var idpParam = (requestParams.GetValues("idp") ?? throw new InvalidOperationException()).Last();
        var scope = (requestParams.GetValues("scope") ?? throw new InvalidOperationException()).First();
        var clientRedirectUrl = (requestParams.GetValues("redirect_uri") ?? throw new InvalidOperationException()).Last();
        var updateRegistration = requestParams.GetValues("update_registration")?.Last();

        // Validate idp Server;
        var idpUri = new Uri(idpParam);
        var communityParam = (HttpUtility.ParseQueryString(idpUri.Query).GetValues("community") ?? Array.Empty<string>()).LastOrDefault();
        var idp = idpUri.OriginalString;
        if (communityParam != null)
        {
            if (idp.Contains($":{{idpUri.Port}}"))
            {
                idp = $"{idpUri.Scheme}{Uri.SchemeDelimiter}{idpUri.Host}:{idpUri.Port}{idpUri.LocalPath}";
            }
            else
            {
                idp = $"{idpUri.Scheme}{Uri.SchemeDelimiter}{idpUri.Host}{idpUri.LocalPath}";
            }
        }
        
        _udapClient.Problem += element => properties.Parameters.Add("Problem", element.ChainElementStatus.Summarize(TrustChainValidator.DefaultProblemFlags));
        _udapClient.Untrusted += certificate2 => properties.Parameters.Add("Untrusted", certificate2.Subject);
        _udapClient.TokenError += message => properties.Parameters.Add("TokenError", message);
        
        var response = await _udapClient.ValidateResource(idp, communityParam);
        
        var resourceHolderRedirectUrl =
            $"{Context.Request.Scheme}{Uri.SchemeDelimiter}{Context.Request.Host}{Options.CallbackPath}";

        if (response.IsError)
        {
            Logger.LogError(response.Error);


            var untrustedContext = new UdapUntrustedContext(Context, Scheme, Options, properties);
            Response.StatusCode = 401;

            // await Response.WriteAsJsonAsync(_udapClient.UdapServerMetaData);

            foreach (var prop in properties.Parameters.Where(p => p.Key == "Untrusted").Select(p => p))
            {
                await Response.WriteAsync($"{prop.Key}: {prop.Value}"); 
            }

            await Response.Body.FlushAsync();

            return;
        }


        Logger.LogInformation($"Validated UDAP signed_metadata from {idp}");
        Logger.LogDebug(JsonSerializer.Serialize(
            _udapClient.UdapServerMetaData,
            new JsonSerializerOptions { WriteIndented = true }));

        //
        // if not registered with IdP, then register.
        //

        var idpClient = await _udapClientRegistrationStore.FindTieredClientById(idp);

        var idpClientId = null as string;

        if (idpClient != null)
        {
            idpClientId = idpClient.ClientId;
        }

        // TODO Special provision query param updateRegistration to enable update registration.
        // Not sure if it stays here or lives in an Admin tool.
        if (idpClient == null || !idpClient.Enabled || updateRegistration == "true")
        {
            await _certificateStore.Resolve();
            var communityName = communityParam ?? _certificateStore.IssuedCertificates.First().Community;
            var communityId = await _udapClientRegistrationStore.GetCommunityId(communityName, Context.RequestAborted);

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
            var document = await _udapClient.RegisterTieredClient(
                resourceHolderRedirectUrl,

                communityParam == null 
                    ? 
                    new List<X509Certificate2>(){ _certificateStore.IssuedCertificates.First().Certificate } 
                    :
                    _certificateStore.IssuedCertificates.Where(ic => ic.Community == communityParam)
                        .Select(ic => ic.Certificate),

                OptionsMonitor.CurrentValue.Scope.ToSpaceSeparatedString(),
                Context.RequestAborted);

            if (idpClient == null)
            {
                idpClientId = document.ClientId;
            }
          
            var tokenHandler = new JsonWebTokenHandler();
            var jsonWebToken = tokenHandler.ReadJsonWebToken(document.SoftwareStatement);
            var publicCert = jsonWebToken.GetPublicCertificate();
            
            var tieredClient = new TieredClient
            {
                ClientName = document.ClientName,
                ClientId = document.ClientId,
                IdPBaseUrl = idp,
                RedirectUri = clientRedirectUrl,
                ClientUriSan = publicCert.GetSubjectAltNames().First().Item2,   //TODO: can a AuthServer register multiple times per community?
                CommunityId = communityId.Value,
                Enabled = true
            };
            
            await _udapClientRegistrationStore.UpsertTieredClient(tieredClient, Context.RequestAborted);
        }

        properties.SetString("client_id", idpClientId);

        await base.HandleChallengeAsync(properties);
    }


    private static void AddQueryString<T>(
        IDictionary<string, string> queryStrings,
        AuthenticationProperties properties,
        string name,
        Func<T, string?> formatter,
        T defaultValue,
        bool retainAuthProperty = false)
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

        if (!retainAuthProperty)
        {
            // Remove the parameter from AuthenticationProperties so it won't be serialized into the state
            properties.Items.Remove(name);
        }
        
        if (value != null)
        {
            queryStrings[name] = value;
        }
    }

    private static void AddQueryString(
        IDictionary<string, string> queryStrings,
        AuthenticationProperties properties,
        string name,
        bool retainAuthProperty = false,
        string? defaultValue = null)
        => AddQueryString(queryStrings, properties, name, x => x, defaultValue, retainAuthProperty);
}