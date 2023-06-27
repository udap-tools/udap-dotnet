// #region (c) 2023 Joseph Shook. All rights reserved.
// // /*
// //  Authors:
// //     Joseph Shook   Joseph.Shook@Surescripts.com
// // 
// //  See LICENSE in the project root for license information.
// // */
// #endregion
//
// using System.IdentityModel.Tokens.Jwt;
// using System.Security.Cryptography.X509Certificates;
// using System.Text.Json;
// using Duende.IdentityServer;
// using Duende.IdentityServer.Models;
// using Duende.IdentityServer.Stores;
// using IdentityModel;
// using Microsoft.AspNetCore.Authentication;
// using Microsoft.AspNetCore.Authentication.OAuth;
// using Microsoft.AspNetCore.Http;
// using Microsoft.AspNetCore.Mvc.RazorPages;
// using Microsoft.Extensions.Logging;
// using Microsoft.Extensions.Primitives;
// using Microsoft.IdentityModel.JsonWebTokens;
// using Udap.Client.Client;
// using Udap.Common.Certificates;
// using Udap.Common.Extensions;
// using Udap.Model.Registration;
// using Udap.Server.Extensions;
// using Udap.Server.Security.Authentication.TieredOAuth;
// using Udap.Server.Storage.Stores;
// using static Udap.Server.Constants;
//
// namespace Udap.Server.Hosting;
//
// internal class UdapTieredOAuthMiddleware
// {
//     private readonly RequestDelegate _next;
//     private readonly IUdapClient _udapClient;
//     private readonly IPrivateCertificateStore _certificateStore;
//     private readonly TieredOAuthAuthenticationHandler _authHandler;
//     private readonly ILogger<UdapTokenResponseMiddleware> _logger;
//
//     public UdapTieredOAuthMiddleware(
//         RequestDelegate next,
//         IUdapClient udapClient,
//         IPrivateCertificateStore certificateStore,
//         TieredOAuthAuthenticationHandler authHandler,
//         ILogger<UdapTokenResponseMiddleware> logger)
//     {
//         _next = next;
//         _udapClient = udapClient;
//         _certificateStore = certificateStore;
//         _authHandler = authHandler;
//         _logger = logger;
//     }
//
//
//     /// <summary>
//     /// 
//     /// </summary>
//     /// <param name="context"></param>
//     /// <param name="clients"></param>
//     /// <param name="manifest"></param>
//     /// <returns></returns>
//     public async Task Invoke(
//         HttpContext context,
//         IClientStore clients,
//         IUdapClientRegistrationStore store)
//     {
//
//
//
//         if (1 == 0)
//         {
//
//
//             if (context.Request.Path.Value != null &&
//                 context.Request.Path.Value.Contains(Constants.ProtocolRoutePaths.Authorize))
//             {
//
//                 var requestParams = context.Request.Query;
//
//                 if (requestParams.Any())
//                 {
//                     if (requestParams.TryGetValue("idp", out var idplist))
//                     {
//                         // if idp is present, then this is a Tiered OAuth request.
//                         var idp = idplist.Last();
//                         if (idp != null)
//                         {
//                             var redirectUrlList = requestParams["redirect_uri"].ToList();
//                             var scope = requestParams["scope"];
//                             var clientRedirectUrl = redirectUrlList.Last();
//                             if (clientRedirectUrl != null)
//                             {
//                                 // Validate idp Server;
//                                 var community = idp.GetCommunityFromQueryParams();
//                                 var response = await _udapClient.ValidateResource(idp, community);
//                                 var resourceHolderRedirectUrl =
//                                     $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}{TieredOAuthAuthenticationDefaults.CallbackPath}";
//
//                                 if (response.IsError)
//                                 {
//                                     _logger.LogError(response.Error);
//                                     return;
//                                 }
//                                 else
//                                 {
//                                     _logger.LogInformation(JsonSerializer.Serialize(
//                                         _udapClient.UdapServerMetaData,
//                                         new JsonSerializerOptions { WriteIndented = true }));
//                                 }
//
//                                 var updateRegistration = requestParams["update_registration"];
//                                 // if not registered then register.
//                                 var idpClient = await clients.FindClientByIdAsync(idp);
//
//
//                                 var idpClientId = null as string;
//
//                                 if (idpClient != null)
//                                 {
//                                     idpClientId = idpClient.ClientSecrets
//                                         .SingleOrDefault(cs => cs.Type == "TIERED_OAUTH_CLIENT_ID")?.Value;
//                                 }
//
//                                 // TODO Special provision query param updateRegistration to enable update registration.
//                                 // Not sure if it stays here or lives in an Admin tool.
//                                 if (idpClient == null || !idpClient.Enabled || updateRegistration == "true")
//                                 {
//                                     await _certificateStore.Resolve();
//
//
//                                     var communityName = _certificateStore.IssuedCertificates.First().Community;
//
//                                     var communityId =
//                                         await store.GetCommunityId(communityName, GetCancellationToken(context));
//
//                                     if (communityId == null)
//                                     {
//                                         _logger.LogInformation(
//                                             "Tiered Oauth: Cannot find communityId for community: {communityName}",
//                                             communityName);
//                                         //Todo: return strategy?
//                                         return;
//                                     }
//
//                                     //TODO: RegisterClient should be typed to the two builders
//                                     // UdapDcrBuilderForAuthorizationCode or UdapDcrBuilderForClientCredentials
//                                     var document = await _udapClient.RegisterClient(
//                                         resourceHolderRedirectUrl,
//                                         _certificateStore.IssuedCertificates.Where(ic => ic.IdPBaseUrl == idp)
//                                             .Select(ic => ic.Certificate),
//                                         GetCancellationToken(context));
//
//                                     idpClientId = document.ClientId;
//
//                                     var tokenHandler = new JsonWebTokenHandler();
//                                     var jsonWebToken = tokenHandler.ReadJsonWebToken(document.SoftwareStatement);
//                                     var jwtHeader = JwtHeader.Base64UrlDeserialize(jsonWebToken.EncodedHeader);
//
//                                     var x5cArray = Getx5c(jwtHeader);
//                                     var publicCert = new X509Certificate2(Convert.FromBase64String(x5cArray.First()));
//
//
//                                     var client = new Duende.IdentityServer.Models.Client
//                                     {
//                                         ClientId = idp,
//                                         ClientName = document.ClientName,
//                                     };
//
//                                     var clientSecrets = client.ClientSecrets = new List<Secret>();
//
//                                     clientSecrets.Add(new()
//                                     {
//                                         Expiration = publicCert.NotAfter,
//                                         Type = UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME,
//                                         Value = idp
//                                     });
//
//                                     clientSecrets.Add(new()
//                                     {
//                                         Expiration = publicCert.NotAfter,
//                                         Type = UdapServerConstants.SecretTypes.UDAP_COMMUNITY,
//                                         Value = communityId
//                                     });
//
//                                     //TODO: Temp solution.  Need to create first class UdapTieredOAuthClient entity instead
//                                     clientSecrets.Add(new()
//                                     {
//                                         Expiration = publicCert.NotAfter,
//                                         Type = "TIERED_OAUTH_CLIENT_ID",
//                                         Value = document.ClientId
//                                     });
//
//                                     client.AllowedGrantTypes.Add(GrantType.AuthorizationCode);
//
//                                     if (document.GrantTypes != null &&
//                                         document.GrantTypes.Contains(OidcConstants.GrantTypes.RefreshToken))
//                                     {
//                                         if (client.AllowedGrantTypes.Count == 1 &&
//                                             client.AllowedGrantTypes.FirstOrDefault(t =>
//                                                 t.Equals(GrantType.ClientCredentials)) != null)
//                                         {
//                                             // TODO: Technique in UdapClientRegistrationValidator.ValidateClientSecretsAsync
//                                             // return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
//                                             //     UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
//                                             //     "client credentials does not support refresh tokens"));
//
//                                             context.Response.StatusCode = StatusCodes.Status400BadRequest;
//
//                                             var error = new UdapDynamicClientRegistrationErrorResponse
//                                             (
//                                                 UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
//                                                 UdapDynamicClientRegistrationErrorDescriptions
//                                                     .ClientCredentialsRefreshError
//                                             );
//                                             _logger.LogWarning(JsonSerializer.Serialize(error));
//
//                                             await context.Response.WriteAsJsonAsync(error,
//                                                 cancellationToken: GetCancellationToken(context));
//
//                                             return;
//                                         }
//
//                                         client.AllowOfflineAccess = true;
//                                     }
//
//
//                                     //
//                                     // validate redirect URIs and ResponseTypes, add redirect_url
//                                     //
//                                     if (client.AllowedGrantTypes.Contains(GrantType.AuthorizationCode))
//                                     {
//                                         if (document.RedirectUris != null && document.RedirectUris.Any())
//                                         {
//                                             foreach (var requestRedirectUri in document.RedirectUris)
//                                             {
//                                                 //TODO add tests and decide how to handle invalid Uri exception
//                                                 var uri = new Uri(requestRedirectUri);
//
//                                                 if (uri.IsAbsoluteUri)
//                                                 {
//                                                     client.RedirectUris.Add(uri.OriginalString);
//                                                     //TODO: I need to create a policy engine or dig into the Duende policy stuff and see it if makes sense
//                                                     //Threat analysis?
//                                                     client.RequirePkce = false;
//                                                     client.AllowOfflineAccess = true;
//                                                 }
//                                                 else
//                                                 {
//                                                     var error = new UdapDynamicClientRegistrationErrorResponse
//                                                     (
//                                                         UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
//                                                         UdapDynamicClientRegistrationErrorDescriptions
//                                                             .MalformedRedirectUri
//                                                     );
//
//                                                     await context.Response.WriteAsJsonAsync(error,
//                                                         cancellationToken: GetCancellationToken(context));
//
//                                                     return;
//                                                 }
//                                             }
//                                         }
//                                         else
//                                         {
//                                             var error = new UdapDynamicClientRegistrationErrorResponse
//                                             (
//                                                 UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
//                                                 UdapDynamicClientRegistrationErrorDescriptions
//                                                     .RedirectUriRequiredForAuthCode
//                                             );
//
//                                             await context.Response.WriteAsJsonAsync(error,
//                                                 cancellationToken: GetCancellationToken(context));
//
//                                             return;
//                                         }
//
//                                         if (document.ResponseTypes != null && document.ResponseTypes.Count == 0)
//                                         {
//                                             _logger.LogWarning(
//                                                 $"{UdapDynamicClientRegistrationErrors.InvalidClientMetadata}::" +
//                                                 UdapDynamicClientRegistrationErrorDescriptions.ResponseTypesMissing);
//
//                                             var error = new UdapDynamicClientRegistrationErrorResponse
//                                             (
//                                                 UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
//                                                 UdapDynamicClientRegistrationErrorDescriptions.ResponseTypesMissing
//                                             );
//
//                                             await context.Response.WriteAsJsonAsync(error,
//                                                 cancellationToken: GetCancellationToken(context));
//
//                                             return;
//                                         }
//                                     }
//
//
//                                     var upsertFlag = await store.UpsertClient(client, GetCancellationToken(context));
//                                 }
//
//                                 // Authentication request (including openid scope)
//
//                                 var resourceHolderState = CryptoRandom.CreateUniqueId();
//
//                                 var user = new TieredOAuthUser(resourceHolderState)
//                                 {
//                                     DisplayName = $"Tiered OAuth [{idp}]",
//
//                                 };
//
//                                 var props = new AuthenticationProperties
//                                 {
//                                     Items =
//                                     {
//                                         new KeyValuePair<string, string?>(TieredOAuthConstants.ClientRandomState,
//                                             requestParams["state"]),
//                                         new KeyValuePair<string, string?>(TieredOAuthConstants.ResourceHolderRandomState,
//                                             resourceHolderState),
//                                         new KeyValuePair<string, string?>(JwtClaimTypes.Scope, scope)
//                                     },
//                                 };
//
//
//
//                                 // await context.SignInAsync(await context.GetCookieAuthenticationSchemeAsync(), user.CreatePrincipal(), props);
//                                 await context.SignInAsync(user.CreatePrincipal(), props);
//
//
//                                 var authProperties = new AuthenticationProperties();
//                                 authProperties.Parameters.Add("state", resourceHolderState);
//                                 authProperties.Parameters.Add("client_id", idpClientId);
//                                 authProperties.Parameters.Add("redirect_uri", resourceHolderRedirectUrl);
//                                 authProperties.Parameters.Add("response_type", "code");
//                                 authProperties.Parameters.Add("display", "page");
//                                 authProperties.Parameters.Add("scope", "openid udap email profile");
//
//                                 _authHandler.InitializeAsync(
//                                     new AuthenticationScheme(TieredOAuthAuthenticationDefaults.AuthenticationScheme,
//                                         "hello", typeof(TieredOAuthAuthenticationHandler))
//                                     , context);
//                                 var location = _authHandler.BuildUrl(authProperties, resourceHolderRedirectUrl);
//
//                                 // var location = $"{idp}/connect/authorize?" +
//                                 //                $"state={resourceHolderState}&" +
//                                 //                $"client_id={idpClientId}&" +
//                                 //                $"redirect_uri={resourceHolderRedirectUrl}&" +
//                                 //                $"response_type=code&" +
//                                 //                $"display=page&" +
//                                 //                $"scope=openid udap email profile"; //udap could be optional if the relationship to the IdP Server is not UDAP
//                                 //
//                                 // // redirect
//
//                                 context.Response.Redirect(location, false);
//
//                                 return;
//                             }
//
//                             _logger.LogInformation("Tiered Oauth: missing redirect_uri");
//                         }
//                     }
//                 }
//             }
//         }
//
//         await _next(context);
//
//     }
//
//     private readonly string[]? _x5cArray = null;
//     //Todo: duplicate code
//     private string[]? Getx5c(JwtHeader jwtHeader)
//     {
//         if (_x5cArray != null && _x5cArray.Any()) return _x5cArray;
//
//         if (jwtHeader.X5c == null)
//         {
//             return null;
//         }
//
//         var x5cArray = JsonSerializer.Deserialize<string[]>(jwtHeader.X5c);
//
//         if (x5cArray != null && !x5cArray.Any())
//         {
//             return null;
//         }
//
//         return x5cArray;
//     }
//
//     private CancellationToken GetCancellationToken(HttpContext? context)
//     {
//         return context?.RequestAborted ?? CancellationToken.None;
//     }
//
//
//     private string BuildTieredOAuthRedirectUrl(StringValues idp, IQueryCollection requestParams)
//     {
//         if (idp.Count > 1)
//         {
//             throw new ArgumentException("Only one idp is supported", nameof(idp));
//         }
//
//         var uri = idp + "/connect/authorize?" + requestParams
//             .Where(param => param.Key != "idp")
//             .Select(param => $"{param.Key}={param.Value}")
//             .Aggregate((current, next) => $"{current}&{next}");
//
//         return uri;
//     }
// }