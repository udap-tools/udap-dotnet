#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Udap.Client.Client.Messages;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using Udap.Util.Extensions;

namespace Udap.Server.Registration;

/// <summary>
/// Registration Endpoint for <A href="https://www.udap.org/udap-dynamic-client-registration-stu1.html#section-5.1">
/// UDAP Dynamic Client Registration</A>
/// </summary>
public class UdapDynamicClientRegistrationEndpoint
{
    private readonly IUdapDynamicClientRegistrationValidator _validator;
    private readonly IUdapClientRegistrationStore _store;
    private readonly ServerSettings _serverSettings;
    private readonly ILogger<UdapDynamicClientRegistrationEndpoint> _logger;

    public UdapDynamicClientRegistrationEndpoint(
        IUdapDynamicClientRegistrationValidator validator,
        IUdapClientRegistrationStore store,
        ServerSettings serverSettings,
        ILogger<UdapDynamicClientRegistrationEndpoint> logger)
    {
        _validator = validator;
        _store = store;
        _serverSettings = serverSettings;
        _logger = logger;
    }
    
    //TODO: ProcessAsync?
    /// <summary>
    /// Initiate UDAP Dynamic Client Registration for <see cref="UdapDynamicClientRegistrationEndpoint"/>
    /// </summary>
    /// <param name="context"></param>
    /// <returns></returns>
    public async Task Process(HttpContext context)
    {
        //
        // Can't tell if this is truly required from specifications.
        // Maybe search the DCR RFC's
        // National Directory client seems to be missing this header.
        // Maybe discuss this at the next UDAP meeting.
        //
        if (!context.Request.HasJsonContentType())
        {
            context.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
            return;
        }

        UdapRegisterRequest request;
        try
        {
            request = await context.Request.ReadFromJsonAsync<UdapRegisterRequest>() ?? throw new ArgumentNullException();
        }
        catch (Exception)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsJsonAsync(new UdapDynamicClientRegistrationErrorResponse
            {
                Error = UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                ErrorDescription = "malformed metadata document"
            });
            
            return;
        }

        var community = context.Request.Query[UdapConstants.Community];
        
        var rootCertificates = await _store.GetRootCertificates();
        var communityTrustAnchors = await _store.GetAnchorsCertificates(community);

        //TODO: null work
        UdapDynamicClientRegistrationValidationResult result = null;

        try
        {
            // Not in pattern with other validators in IdentityServer.  Typically all errors handled in ValidateAsync...  TODO

            result = await _validator.ValidateAsync(request, communityTrustAnchors, rootCertificates);


            // TODO: Need a policy engine for various things.  UDAP ServerMode allows and empty scope during registration.
            // So some kind of policy linked to maybe issued certificate certification and/or community or something
            // There are a lot of choices left up to a community.  The HL7 ServerMode requires scopes to be sent during registration.
            // This doesn't mean the problem is easier it just means  we could filter down during registration even if policy
            // allowed for a broader list of scopes.
            // Below I use ServerSettings from appsettings.  This basically says that server is either UDAP or HL7 mode.  Well
            // sort of.  The code is only trying to pass udap.org tests and survive a HL7 connect-a-thon. By putting the logic in
            // a policy engine we can have one server UDAP and Hl7 Mode or whatever the policy engine allows.  

            //
            // Also there should be a better way to do this.  It will repeat many scope entries per client.
            //
            if ( !result.IsError && _serverSettings.ServerSupport == ServerSupport.UDAP )
            {
                if (string.IsNullOrWhiteSpace(result.Document.Scope))
                {
                    var scopes = _serverSettings.DefaultScopes?.FromSpaceSeparatedString();
                    if (scopes != null)
                    {
                        foreach (var scope in scopes)
                        {
                            result.Client?.AllowedScopes.Add(scope);
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled UdapDynamicClientRegistrationEndpoint Error");
        }

        if (result.IsError)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            
            var error = new UdapDynamicClientRegistrationErrorResponse
            {
                Error = result.Error,
                ErrorDescription = result.ErrorDescription
            };
            
            _logger.LogWarning(JsonSerializer.Serialize(error));

            await context.Response.WriteAsJsonAsync(error);

            return;
        }

        // var anchors = (await _store.GetAnchors()).ToList();

        var saved = await _store.AddClient(result.Client);

        if (saved == 0)
        {
            await context.Response.WriteAsJsonAsync(new UdapDynamicClientRegistrationErrorResponse
            {
                Error = UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                ErrorDescription = "Udap registration failed to save a client."
            });

            return;
        }
        

        var registrationResponse = BuildResponseDocument(request, result);

        var options = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };
        
        context.Response.StatusCode = StatusCodes.Status201Created;
        await context.Response.WriteAsJsonAsync(registrationResponse, options, "application/json");
    }


    //
    // RFC7591 DCR, states, 
    // If a software statement was used as part of the registration, its
    // value MUST be returned unmodified in the response along with other
    // metadata using the "software_statement" member name.  Client metadata
    // elements used from the software statement MUST also be returned
    // directly as top-level client metadata values in the registration
    // response(possibly with different values, since the values requested
    // and the values used may differ).
    //
    private static UdapDynamicClientRegistrationDocument BuildResponseDocument(UdapRegisterRequest request,
        UdapDynamicClientRegistrationValidationResult result)
    {
        var registrationResponse = new UdapDynamicClientRegistrationDocument()
        {
            ClientId = result.Client.ClientId,
            SoftwareStatement = request.SoftwareStatement
        };

        //
        // result.Document is the UdapDynamicClientRegistrationDocument originally sent as the 
        // software_statement and thus all members must be returned as top-level elements.
        //
        foreach (var pair in result.Document)
        {
            registrationResponse.Add(pair.Key, pair.Value);
        }

        return registrationResponse;
    }
}