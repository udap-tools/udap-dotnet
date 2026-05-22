#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

//
// Most of this file is copied from Duende's Identity Server dom/dcr-proc branch
//
//

using Duende.IdentityModel;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.WebUtilities; // added
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Mime;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using Udap.Server.Validation;
using Udap.Util.Extensions;

namespace Udap.Server.Registration;

/// <summary>
/// UDAP Validator
/// </summary>
public class UdapDynamicClientRegistrationValidator : IUdapDynamicClientRegistrationValidator
{
    private readonly TrustChainValidator _trustChainValidator;
    private readonly HttpClient _httpClient;
    private readonly IReplayCache _replayCache;
    private readonly ILogger _logger;
    private readonly ServerSettings _serverSettings;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IScopeExpander _scopeExpander;
    private readonly IResourceStore _resourceStore;

    private const string Purpose = nameof(UdapDynamicClientRegistrationValidator);

    public UdapDynamicClientRegistrationValidator(
        TrustChainValidator trustChainValidator,
        HttpClient httpClient,
        IReplayCache replayCache,
        ServerSettings serverSettings,
        IHttpContextAccessor httpContextAccessor,
        IScopeExpander scopeExpander,
        IResourceStore resourceStore, //TODO use CachingResourceStore
        ILogger<UdapDynamicClientRegistrationValidator> logger)
    {
        _trustChainValidator = trustChainValidator;
        _httpClient = httpClient;
        _replayCache = replayCache;
        _serverSettings = serverSettings;
        _httpContextAccessor = httpContextAccessor;
        _scopeExpander = scopeExpander;
        _resourceStore = resourceStore;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<UdapDynamicClientRegistrationValidationResult> ValidateAsync(
        UdapDynamicClientRegistrationContext context,
        X509Certificate2Collection? intermediateCertificates,
        X509Certificate2Collection anchorCertificates,
        IEnumerable<Anchor>? anchors
        )
    {
        using var activity = Tracing.ValidationActivitySource.StartActivity();

        var request = context.Request;

        //////////////////////////////
        // validate udap version
        //////////////////////////////
        // The UDAP base protocol (udap.org) is at version 1. Both SSRAA STU 1.1 and STU 2.0
        // profile UDAP v1, so this field is always "1". Which SSRAA IG version the server
        // enforces is a server-side policy (SsraaVersion in ServerSettings).
        if (string.IsNullOrEmpty(request.Udap))
        {
            _logger.LogWarning("{Error}::{Description}",
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.MissingUdapVersion);

            return new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.MissingUdapVersion);
        }

        if (request.Udap != UdapConstants.UdapVersionsSupportedValue)
        {
            var errorDescription = string.Format(
                UdapDynamicClientRegistrationErrorDescriptions.UnsupportedUdapVersion,
                UdapConstants.UdapVersionsSupportedValue);

            _logger.LogWarning("{Error}::{Description}",
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                errorDescription);

            return new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                errorDescription);
        }

        var tokenHandler = new JsonWebTokenHandler();
        var jsonWebToken = tokenHandler.ReadJsonWebToken(request.SoftwareStatement);
        var jwtHeader = JwtHeader.Base64UrlDeserialize(jsonWebToken.EncodedHeader);

        var x5cArray = Getx5c(jwtHeader);

        if (x5cArray == null)
        {
            return await Task.FromResult(
                new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                    UdapDynamicClientRegistrationErrorDescriptions.CannotFindorParseX5c));
        }

#if NET9_0_OR_GREATER
        var publicCert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(x5cArray.First()));
#else
        var publicCert = new X509Certificate2(Convert.FromBase64String(x5cArray.First()));
#endif
        var subAltNames = publicCert.GetSubjectAltNames(n => n.TagNo == (int)X509Extensions.GeneralNameType.URI);
        TokenValidationResult? validatedToken;
        var publicKey = publicCert.PublicKey.GetRSAPublicKey();

        if (publicKey != null)
        {
            validatedToken = await tokenHandler.ValidateTokenAsync(request.SoftwareStatement,
                new TokenValidationParameters
                {
                    RequireSignedTokens = true,
                    ValidateIssuer = true,
                    // Udap section 4.3 is strict concerning the SANs being of type uniformResourceIdentifier. https://www.udap.org/udap-dynamic-client-registration.html
                    // See RFC 2459 for SAN choice semantics https://www.rfc-editor.org/rfc/rfc2459#section-4.2.1.7
                    ValidIssuers = subAltNames.Select(san => san.Item2).ToArray(),
                    //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                    ValidateAudience = false, // No aud for UDAP metadata
                    ValidateLifetime = true,
                    IssuerSigningKey = new X509SecurityKey(publicCert),
                    ValidAlgorithms = [jsonWebToken.Alg], //must match signing algorithm
                    // AudienceValidator = (audiences, token, parameters) =>  Potential enhanced validation.  or replace inline validation code below
                }
            );
        }
        else
        {
            var ecdsaPublicKey = publicCert.PublicKey.GetECDsaPublicKey();

            validatedToken = await tokenHandler.ValidateTokenAsync(request.SoftwareStatement,
                new TokenValidationParameters
                {
                    RequireSignedTokens = true,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuers = subAltNames.Select(san => san.Item2).ToArray(),
                    ValidateAudience = false, // No aud for UDAP metadata
                    ValidateLifetime = true,
                    IssuerSigningKey = new ECDsaSecurityKey(ecdsaPublicKey),
                    ValidAlgorithms = [jsonWebToken.Alg], //must match signing algorithm
                });
        }

        _logger.LogDebug("Is token valid: {IsValid}", validatedToken.IsValid);

        if (!validatedToken.IsValid)
        {
            if (validatedToken.Exception.GetType() == typeof(SecurityTokenNoExpirationException))
            {
                return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                    UdapDynamicClientRegistrationErrorDescriptions.ExpMissing));
            }

            if (validatedToken.Exception.GetType() == typeof(SecurityTokenExpiredException))
            {
                return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                    $"{UdapDynamicClientRegistrationErrorDescriptions.ExpExpired}: {validatedToken.Exception.Message}"));
            }

            _logger.LogWarning(validatedToken.Exception, "Invalid software statement: {Error}", UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.FailedTokenValidation));
        }

        var document = new UdapDynamicClientRegistrationDocument();
        document.AddClaims(jsonWebToken.Claims);

        if (_serverSettings.RegistrationJtiRequired)
        {
            var result = await ValidateJti(document, document.Expiration.GetValueOrDefault());

            if (result.IsError)
            {
                return result;
            }
        }

        if (document.Subject == null)
        {
            _logger.LogWarning("{Error}::{Description}",
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.SubIsMissing);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.SubIsMissing));
        }

        if (document.Subject != document.Issuer)
        {
            _logger.LogWarning("{Error}::{Description}",
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.SubNotEqualToIss);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.SubNotEqualToIss));
        }

        if (!Uri.TryCreate(document.Audience, UriKind.Absolute, out var aud))
        {
            _logger.LogWarning("{Error}::{Description}: {Aud}",
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.InvalidAud,
                aud);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                $"{UdapDynamicClientRegistrationErrorDescriptions.InvalidAud}: {aud}"));
        }

        var endpoint = new Uri(_httpContextAccessor.HttpContext!.Request.GetDisplayUrl());

        if (Uri.Compare(endpoint, aud,
                UriComponents.Host | UriComponents.PathAndQuery | UriComponents.Port,
                UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase)
            != 0)
        {
            _logger.LogWarning("{Error}::{Description}",
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.InvalidMatchAud);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                $"{UdapDynamicClientRegistrationErrorDescriptions.InvalidMatchAud}"));
        }

        //TODO Server Config for iat window (clock skew?)
        if (document.IssuedAt == 0)
        {
            _logger.LogWarning("{Error}::{Description}",
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.IssuedAtMissing);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.IssuedAtMissing));
        }

        var iat = EpochTime.DateTime(document.IssuedAt.GetValueOrDefault()).ToUniversalTime();
        //TODO Server Config for iat window (clock skew?)
        if (iat > DateTime.UtcNow.AddSeconds(5))
        {
            _logger.LogWarning("{Error}::{Description}",
                   UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                   UdapDynamicClientRegistrationErrorDescriptions.IssuedAtInFuture);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.IssuedAtInFuture));
        }

        if (string.IsNullOrEmpty(document.ClientName))
        {
            _logger.LogWarning("{Error}::{Description}",
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.ClientNameMissing);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.ClientNameMissing));
        }

        if (string.IsNullOrEmpty(document.TokenEndpointAuthMethod))
        {
            _logger.LogWarning("{Error}::{Description}",
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.TokenEndpointAuthMethodMissing);

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.TokenEndpointAuthMethodMissing));
        }

        // Populate context with parsed JWT state
        context.Document = document;
        context.JsonWebToken = jsonWebToken;
        context.JwtHeader = jwtHeader;
        context.ClientCertificate = publicCert;

        _logger.LogDebug("Validating chain. x5c {X5c}", jwtHeader.X5c);

        if (!await ValidateChainAsync(context, jsonWebToken, jwtHeader, intermediateCertificates, anchorCertificates, anchors))
        {
            _logger.LogWarning("{Error}::{Description}",
                UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.UntrustedCertificate);

            var sb = new StringBuilder();
            sb.AppendLine($"Client Thumbprint: {publicCert.Thumbprint}");

            if (intermediateCertificates != null)
            {
                sb.AppendLine(
                    $"Intermediate Thumbprints: {string.Join(" | ", intermediateCertificates.Select(a => a.Thumbprint))}");

            }

            sb.AppendLine($"Anchor Certificate Thumbprints: {string.Join(" | ", anchorCertificates.Select(a => a.Thumbprint))}");
            _logger.LogWarning("{Message}", sb.ToString());

            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement,
                UdapDynamicClientRegistrationErrorDescriptions.UntrustedCertificate));
        }

        _logger.LogDebug("Chain Validated");

        var (org, dataHolder) = ResolveOrgAndDataHolder(_httpContextAccessor.HttpContext, aud);
        context.Organization = org;
        context.DataHolder = dataHolder;

        //////////////////////////////
        // validate grant_types
        //////////////////////////////
        if (jsonWebToken.Claims.FirstOrDefault(c => c.Type == UdapConstants.RegistrationDocumentValues.GrantTypes) == null)
        {
            //
            // The jsonWeToken.Claims will always drop an empty array.  So we can not tell the difference
            // between a Cancel Registration (empty array of grant_types) vs an invalid_client_metadata error.
            // So in this path we look at the payload for the grant_types string.
            //
            var payload = Base64UrlEncoder.Decode(jsonWebToken.EncodedPayload);

            if (payload != null)
            {
                if (!payload.Contains(UdapConstants.RegistrationDocumentValues.GrantTypes))
                {
                    _logger.LogWarning("{Error}::{Description}",
                                       UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                                       UdapDynamicClientRegistrationErrorDescriptions.GrantTypeMissing);

                    return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                        UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                        UdapDynamicClientRegistrationErrorDescriptions.GrantTypeMissing));
                }
            }
        }

        // Track recognized grant types for validation purposes (no Client mutation)
        var hasClientCredentials = document.GrantTypes != null && document.GrantTypes.Contains(OidcConstants.GrantTypes.ClientCredentials);
        var hasAuthorizationCode = document.GrantTypes != null && document.GrantTypes.Contains(OidcConstants.GrantTypes.AuthorizationCode);
        var recognizedGrantTypeCount = (hasClientCredentials ? 1 : 0) + (hasAuthorizationCode ? 1 : 0);

        // we only support the two above grant types but, an empty GrantType is an indication of a cancel registration action.
        if (recognizedGrantTypeCount == 0 &&
            document.GrantTypes != null &&
            document.GrantTypes.Count != 0)
        {
            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.UnsupportedGrantType));
        }

        //TODO: Ensure test covers this and follows Security IG: http://hl7.org/fhir/us/udap-security/b2b.html#refresh-tokens
        if (document.GrantTypes != null && document.GrantTypes.Contains(OidcConstants.GrantTypes.RefreshToken))
        {
            if (recognizedGrantTypeCount == 1 && hasClientCredentials)
            {
                return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    UdapDynamicClientRegistrationErrorDescriptions.ClientCredentialsRefreshError));
            }
        }

        //
        // validate redirect URIs and ResponseTypes and logo_uri
        //
        if (hasAuthorizationCode)
        {
            var (successFlag, errorResult) = await ValidateLogoUri(document);

            if (_serverSettings.LogoRequired)
            {
                if (!successFlag)
                {
                    return errorResult!;
                }
            }

            if (document.RedirectUris != null && document.RedirectUris.Count != 0)
            {
                foreach (var requestRedirectUri in document.RedirectUris)
                {
                    //TODO add tests and decide how to handle invalid Uri exception
                    var uri = new Uri(requestRedirectUri);

                    if (!uri.IsAbsoluteUri)
                    {
                        return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                            UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                            UdapDynamicClientRegistrationErrorDescriptions.MalformedRedirectUri));
                    }
                }
            }
            else
            {
                return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    UdapDynamicClientRegistrationErrorDescriptions.RedirectUriRequiredForAuthCode));
            }

            if (document.ResponseTypes != null && document.ResponseTypes.Count == 0)
            {
                _logger.LogWarning($"{UdapDynamicClientRegistrationErrors.InvalidClientMetadata}::" +
                                   UdapDynamicClientRegistrationErrorDescriptions.ResponseTypesMissing);

                return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    UdapDynamicClientRegistrationErrorDescriptions.ResponseTypesMissing));
            }
        }

        if (recognizedGrantTypeCount == 1 && hasClientCredentials)
        {
            //TODO: find the RFC reference for this rule and add a Test
            if (document.RedirectUris != null && document.RedirectUris.Count != 0)
            {
                return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    "redirect URI not compatible with client_credentials grant type"));
            }
        }

        //////////////////////////////
        // validate scopes
        //////////////////////////////

        if (recognizedGrantTypeCount != 0 && //Cancel Registration
            string.IsNullOrEmpty(document.Scope))
        {
            return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                "scope is required"));
        }

        if (!string.IsNullOrWhiteSpace(document.Scope))
        {
            var scopes = document.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            // todo: ideally scope names get checked against configuration store?

            var resources = await _resourceStore.GetAllEnabledResourcesAsync();
            var expandedScopes = _scopeExpander.Expand(scopes).ToList();
            var explodedScopes = _scopeExpander.WildCardExpand(expandedScopes, resources.ApiScopes.Select(a => a.Name).ToList()).ToList();
            var allowedApiScopes = resources.ApiScopes.Where(s => explodedScopes.Contains(s.Name));
            var allowedResourceScopes = resources.IdentityResources.Where(s => explodedScopes.Contains(s.Name));

            var allValidScopes = allowedApiScopes.Select(s => s.Name)
                .Concat(allowedResourceScopes.Select(s => s.Name))
                .ToHashSet();

            if (explodedScopes.All(s => !allValidScopes.Contains(s)))
            {
                return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    "invalid_scope supplied"));
            }

            // Collect resolved scopes and store in context for the processor
            var resolvedScopes = new List<string>();

            foreach (var scope in allowedApiScopes)
            {
                resolvedScopes.Add(scope.Name);
            }

            foreach (var scope in allowedResourceScopes.Where(s => s.Enabled).Select(s => s.Name))
            {
                resolvedScopes.Add(scope);
            }

            context.Items["ResolvedScopes"] = (IEnumerable<string>)resolvedScopes;

            //
            // Present scopes in aggregate form
            //
            document.Scope = _scopeExpander.Aggregate(resolvedScopes).OrderBy(s => s).ToSpaceSeparatedString();
        }

        // validation successful - return document
        _logger.LogDebug("Validation success");

        return await Task.FromResult(new UdapDynamicClientRegistrationValidationResult(document));
    }

    // Extracts org/dataholder from:
    //   Query:  /connect/register?{org}={dataholder}
    // org is the parameter name; the value is any non-empty string.
    private static (string? Org, string? Holder) ResolveOrgAndDataHolder(HttpContext? http, Uri aud)
    {
        if (TryGetOrgHolderFromQuery(aud, out var org, out var holder))
        {
            return (org, holder);
        }

        if (http is not null)
        {
            var requestUri = new Uri(http.Request.GetDisplayUrl());
            if (TryGetOrgHolderFromQuery(requestUri, out org, out holder))
            {
                return (org, holder);
            }
        }

        return (null, null);
    }

    private static bool TryGetOrgHolderFromQuery(Uri uri, out string? org, out string? holder)
    {
        org = null;
        holder = null;

        if (string.IsNullOrEmpty(uri.Query))
        {
            return false;
        }

        var q = QueryHelpers.ParseQuery(uri.Query);

        // Select the first query parameter with a non-empty key and value.
        foreach (var kv in q)
        {
            var key = kv.Key;
            var value = kv.Value.FirstOrDefault();

            if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            org = key;
            holder = value;
            return true;
        }

        return false;
    }


    public async Task<(bool, UdapDynamicClientRegistrationValidationResult?)> ValidateLogoUri(UdapDynamicClientRegistrationDocument document)
    {
        UdapDynamicClientRegistrationValidationResult? errorResult;

        if (string.IsNullOrEmpty(document.LogoUri))
        {
            errorResult = new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.LogoMissing);

            return (false, errorResult);
        }

        if (Uri.TryCreate(document.LogoUri, UriKind.Absolute, out var logoUri))
        {
            _logger.LogDebug("Validating logo: {LogoUri}", logoUri.OriginalString);

            if (!logoUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                errorResult = new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    UdapDynamicClientRegistrationErrorDescriptions.LogoInvalidScheme);

                return (false, errorResult);
            }

            var response = await _httpClient.GetAsync(logoUri.OriginalString);
            response.Content.Headers.TryGetValues("Content-Type", out var contentTypes);
            var contentType = contentTypes?.FirstOrDefault();

            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                errorResult = new UdapDynamicClientRegistrationValidationResult(
                   UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                   UdapDynamicClientRegistrationErrorDescriptions.LogoCannotBeResolved);

                return (false, errorResult);
            }

            if (contentType == null ||
                !contentType.Equals("image/png", StringComparison.OrdinalIgnoreCase) &&
                !contentType.Equals(MediaTypeNames.Image.Jpeg, StringComparison.OrdinalIgnoreCase) &&
                !contentType.Equals(MediaTypeNames.Image.Gif, StringComparison.OrdinalIgnoreCase))
            {
                errorResult = new UdapDynamicClientRegistrationValidationResult(
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    UdapDynamicClientRegistrationErrorDescriptions.LogoInvalidContentType);

                _logger.LogDebug("Logo validation failed: {LogoUri}", logoUri.OriginalString);

                return (false, errorResult);
            }
        }
        else
        {
            errorResult = new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.LogoInvalidUri);

            _logger.LogDebug("Logo validation failed: {LogoUri}", document.LogoUri);

            return (false, errorResult);
        }

        _logger.LogDebug("Logo validation succeeded: {LogoUri}", logoUri.OriginalString);

        return (true, null);
    }

    public async Task<UdapDynamicClientRegistrationValidationResult> ValidateJti(
        UdapDynamicClientRegistrationDocument document,
        long exp)
    {
        var jti = document.JwtId;


        if (jti == null || jti.IsMissing())
        {
            _logger.LogWarning("jti is missing.");
            return new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.InvalidJti);

        }

        if (await _replayCache.ExistsAsync(Purpose, jti))
        {
            _logger.LogWarning("jti is found in replay cache. Possible replay attack.");

            return new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.Replay);
        }
        else
        {
            await _replayCache.AddAsync(Purpose, jti, DateTimeOffset.FromUnixTimeSeconds(exp));
        }

        return new UdapDynamicClientRegistrationValidationResult(string.Empty);
    }

    private async Task<bool> ValidateChainAsync(
        UdapDynamicClientRegistrationContext context,
        JsonWebToken jwtSecurityToken,
        JwtHeader jwtHeader,
        X509Certificate2Collection? intermediateCertificates,
        X509Certificate2Collection anchorCertificates,
        IEnumerable<Anchor>? anchors)
    {
        var x5cArray = Getx5c(jwtHeader);

        // TODO: no test cases for x5c with intermediate certificates.
        if (x5cArray != null)
        {
#if NET9_0_OR_GREATER
            var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(x5cArray.First()));
#else
            var cert = new X509Certificate2(Convert.FromBase64String(x5cArray.First()));
#endif

            var result = await _trustChainValidator.IsTrustedCertificateAsync(
                context.Document?.ClientName ?? string.Empty,
                cert,
                intermediateCertificates,
                anchorCertificates,
                anchors);

            if (result.IsValid)
            {
                if (result.ChainElements.Count == 0)
                {
                    _logger.LogError("Missing chain elements");

                    return false;
                }

                context.Issuer = jwtSecurityToken.Issuer;
                context.CommunityId = result.CommunityId;
                context.CommunityName = result.CommunityName;
                context.CertificateExpiration = result.ChainElements.First().Certificate.NotAfter.ToUniversalTime();

                return true;
            }
        }

        _logger.LogDebug("JWT payload: {EncodedPayload}", jwtSecurityToken.EncodedPayload);
        _logger.LogDebug("x5c: {X5c}", jwtHeader.X5c);

        return false;
    }

    private string[]? _x5cArray;

    //Todo duplicate code
    private string[]? Getx5c(JwtHeader jwtHeader)
    {
        if (_x5cArray != null && _x5cArray.Length != 0) return _x5cArray;

        if (jwtHeader.X5c == null)
        {
            return null;
        }

        var certificates = jwtHeader["x5c"] as List<object>;

        if (certificates == null)
        {
            return null;
        }

        _x5cArray = certificates.Select(c => c.ToString()).ToArray()!;

        return _x5cArray;
    }

}
