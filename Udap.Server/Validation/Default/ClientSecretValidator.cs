// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

//
// Most of this file is copied from Duende's Identity Server
// This implementation has added a IScopeService to attach a specific clients 
// scope to the request form for later validation.  
//

using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Udap.Server.Services;

namespace Udap.Server.Validation.Default;

/// <summary>
/// Validates a client secret using the registered secret validators and parsers
/// </summary>
public class UdapClientSecretValidator : IClientSecretValidator
{
    private readonly ILogger _logger;
    private readonly IClientStore _clients;
    private readonly IEventService _events;
    private readonly ISecretsListValidator _validator;
    private readonly ISecretsListParser _parser;
    private readonly IScopeService _scopeService;

    /// <summary>
    /// Initializes a new instance of the <see cref="ClientSecretValidator"/> class.
    /// </summary>
    /// <param name="clients">The clients.</param>
    /// <param name="parser">The parser.</param>
    /// <param name="validator">The validator.</param>
    /// <param name="events">The events.</param>
    /// <param name="logger">The logger.</param>
    public UdapClientSecretValidator(
        IClientStore clients, 
        ISecretsListParser parser, 
        ISecretsListValidator validator, 
        IEventService events,
        IScopeService scopeService,
        ILogger<ClientSecretValidator> logger)
    {
        _clients = clients;
        _parser = parser;
        _validator = validator;
        _events = events;
        _scopeService = scopeService;
        _logger = logger;
    }

    /// <summary>
    /// Validates the current request.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <returns></returns>
    public async Task<ClientSecretValidationResult> ValidateAsync(HttpContext context)
    {
        using var activity = Udap.Common.Tracing.ValidationActivitySource.StartActivity("ClientSecretValidator.Validate");

        _logger.LogDebug("Start client validation");
        
        var fail = new ClientSecretValidationResult
        {
            IsError = true,
            Error = IdentityModel.OidcConstants.TokenErrors.InvalidClient
        };

        var parsedSecret = await _parser.ParseAsync(context);
        if (parsedSecret == null)
        {
            await RaiseFailureEventAsync("unknown", "No client id found");

            _logger.LogError("No client identifier found");

            fail.Error = IdentityModel.OidcConstants.TokenErrors.InvalidRequest;
            return fail;
        }

        // load client
        var client = await _clients.FindEnabledClientByIdAsync(parsedSecret.Id);
        if (client == null)
        {
            await RaiseFailureEventAsync(parsedSecret.Id, "Unknown client");

            _logger.LogError("No client with id '{clientId}' found. aborting", parsedSecret.Id);
            return fail;
        }

        SecretValidationResult secretValidationResult = null;

        if (!client.RequireClientSecret || client.IsImplicitOnly())
        {
            _logger.LogDebug("Public Client - skipping secret validation success");
        }
        else
        {
            secretValidationResult = await _validator.ValidateAsync(client.ClientSecrets, parsedSecret);
            if (secretValidationResult.Success == false)
            {
                await RaiseFailureEventAsync(client.ClientId, "Invalid client secret");
                _logger.LogError("Client secret validation failed for client: {clientId}.", client.ClientId);

                return fail;
            }
        }

        _logger.LogDebug("Client validation success");


        // resolve scopes
        await _scopeService.Resolve(context, client);
        

        var success = new ClientSecretValidationResult
        {
            IsError = false,
            Client = client,
            Secret = parsedSecret,
            Confirmation = secretValidationResult?.Confirmation
        };

        await RaiseSuccessEventAsync(client.ClientId, parsedSecret.Type);
        return success;
    }

    private Task RaiseSuccessEventAsync(string clientId, string authMethod)
    {
        return _events.RaiseAsync(new ClientAuthenticationSuccessEvent(clientId, authMethod));
    }

    private Task RaiseFailureEventAsync(string clientId, string message)
    {
        return _events.RaiseAsync(new ClientAuthenticationFailureEvent(clientId, message));
    }
}