#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.ResponseHandling;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Udap.Server.Validation;

namespace Udap.Server.ResponseHandling;
public class UdapAuthorizeResponseGenerator : AuthorizeResponseGenerator
{
    private readonly IScopeExpander _scopeExpander;

    /// <summary>
    /// Initializes a new instance of the <see cref="T:Duende.IdentityServer.ResponseHandling.AuthorizeResponseGenerator" /> class.
    /// </summary>
    /// <param name="scopeExpander"></param>
    /// <param name="options">The options.</param>
    /// <param name="clock">The clock.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="tokenService">The token service.</param>
    /// <param name="keyMaterialService"></param>
    /// <param name="authorizationCodeStore">The authorization code store.</param>
    /// <param name="events">The events.</param>
    public UdapAuthorizeResponseGenerator(IScopeExpander scopeExpander, IdentityServerOptions options, ISystemClock clock, ITokenService tokenService, IKeyMaterialService keyMaterialService, IAuthorizationCodeStore authorizationCodeStore, ILogger<AuthorizeResponseGenerator> logger, IEventService events) : base(options, clock, tokenService, keyMaterialService, authorizationCodeStore, logger, events)
    {
        _scopeExpander = scopeExpander;
    }

    /// <summary>
    /// Creates the response for a code flow request
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    protected override async Task<AuthorizeResponse> CreateCodeFlowResponseAsync(ValidatedAuthorizeRequest request)
    {
        Logger.LogDebug("Creating Authorization Code Flow response.");

        var code = await CreateCodeAsync(request);
        code.RequestedScopes = _scopeExpander.Shrink(code.RequestedScopes);

        var id = await AuthorizationCodeStore.StoreAuthorizationCodeAsync(code);

        var response = new AuthorizeResponse
        {
            Issuer = request.IssuerName,
            Request = request,
            Code = id,
            SessionState = request.GenerateSessionStateValue()
        };

        return response;
    }
}
