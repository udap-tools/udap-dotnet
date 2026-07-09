#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.ResponseHandling;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Udap.Model;

namespace Udap.Server.ResponseHandling;
public class UdapTokenResponseGenerator : TokenResponseGenerator
{
    private readonly IProfileService _profile;

    /// <summary>
    /// Initializes a new instance of the <see cref="T:Duende.IdentityServer.ResponseHandling.TokenResponseGenerator" /> class.
    /// </summary>
    /// <param name="profile"></param>
    /// <param name="timeProvider">The time provider.</param>
    /// <param name="tokenService">The token service.</param>
    /// <param name="refreshTokenService">The refresh token service.</param>
    /// <param name="scopeParser">The scope parser.</param>
    /// <param name="resources">The resources.</param>
    /// <param name="clients">The clients.</param>
    /// <param name="logger">The logger.</param>
    public UdapTokenResponseGenerator(
        IProfileService profile,
        TimeProvider timeProvider,
        ITokenService tokenService,
        IRefreshTokenService refreshTokenService,
        IScopeParser scopeParser,
        IResourceStore resources,
        IClientStore clients,
        ILogger<TokenResponseGenerator> logger) : base(timeProvider, tokenService, refreshTokenService, scopeParser, resources, clients, logger)
    {
        _profile = profile;
    }

    /// <summary>
    /// Creates the response for an authorization code request.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns></returns>
    /// <exception cref="System.InvalidOperationException">Client does not exist anymore.</exception>
    protected override async Task<TokenResponse> ProcessAuthorizationCodeRequestAsync(TokenRequestValidationResult request, CancellationToken ct)
    {
        Logger.LogTrace("Creating response for authorization code request");

        var response = await ProcessTokenRequestAsync(request, ct);
        
        if (request.ValidatedRequest.AuthorizationCode == null)
        {
            throw new InvalidOperationException($"Missing {nameof(AuthorizationCode)}.");
        }

        if (request.ValidatedRequest.AuthorizationCode.IsOpenId)
        {
            var tokenRequest = new TokenCreationRequest
            {
                Subject = request.ValidatedRequest.AuthorizationCode.Subject,
                ValidatedResources = request.ValidatedRequest.ValidatedResources,
                Nonce = request.ValidatedRequest.AuthorizationCode.Nonce,
                AccessTokenToHash = response.AccessToken,
                StateHash = request.ValidatedRequest.AuthorizationCode.StateHash,
                ValidatedRequest = request.ValidatedRequest
            };

            var idToken = await TokenService.CreateIdentityTokenAsync(tokenRequest, ct);
            await AugmentClaimsAsync(idToken, request.ValidatedRequest, ct);
            var jwt = await TokenService.CreateSecurityTokenAsync(idToken, ct);
            response.IdentityToken = jwt;
        }

        return response;
    }

    //TODO: Configure propagated claims and test with AspNetIdentity persistence.
    private async Task AugmentClaimsAsync(Token idToken, ValidatedRequest validationResult, CancellationToken ct)
    {
        var context = new ProfileDataRequestContext(
            validationResult.Subject!,
            validationResult.Client,
            IdentityServerConstants.ProfileDataCallers.UserInfoEndpoint,
            new List<string>() { UdapConstants.JwtClaimTypes.Hl7Identifier });
        // context.RequestedResources = validatedResources;

        await _profile.GetProfileDataAsync(context, ct);

        foreach (var contextIssuedClaim in context.IssuedClaims)
        {
            idToken.Claims.Add(contextIssuedClaim);
        }
    }
}
