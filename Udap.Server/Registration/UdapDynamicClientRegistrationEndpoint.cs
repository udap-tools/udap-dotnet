#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Udap.Model.Registration;
using Udap.Server.Storage.Stores;

namespace Udap.Server.Registration;

/// <summary>
/// Registration Endpoint for <A href="https://www.udap.org/udap-dynamic-client-registration-stu1.html#section-5.1">
/// UDAP Dynamic Client Registration</A>
/// See also <A href="https://www.rfc-editor.org/rfc/rfc7591"/>
/// </summary>
public class UdapDynamicClientRegistrationEndpoint
{
    private readonly IUdapDynamicClientRegistrationValidator _validator;
    private readonly IUdapClientRegistrationStore _store;
    private readonly ILogger<UdapDynamicClientRegistrationEndpoint> _logger;

    public UdapDynamicClientRegistrationEndpoint(
        IUdapDynamicClientRegistrationValidator validator,
        IUdapClientRegistrationStore store,
        ILogger<UdapDynamicClientRegistrationEndpoint> logger)
    {
        _validator = validator;
        _store = store;
        _logger = logger;
    }
    
    //TODO: ProcessAsync?
    /// <summary>
    /// Initiate UDAP Dynamic Client Registration for <see cref="UdapDynamicClientRegistrationEndpoint"/>
    /// </summary>
    /// <param name="context"></param>
    /// <param name="token"></param>
    /// <returns></returns>
    public async Task Process(HttpContext context, CancellationToken token)
    {

        if (_logger.IsEnabled(LogLevel.Debug))
        {
            context.Request.EnableBuffering();
            using (var reader = new StreamReader(context.Request.Body, Encoding.UTF8, true, 1024, true))
            {
                var bodyStr = await reader.ReadToEndAsync();
                context.Request.Body.Seek(0, SeekOrigin.Begin);
                _logger.LogDebug("Request: {Request}", bodyStr);
            }
        }

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
            request = await context.Request.ReadFromJsonAsync<UdapRegisterRequest>(cancellationToken: token) ?? throw new ArgumentNullException();
        }
        catch (Exception)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsJsonAsync(new UdapDynamicClientRegistrationErrorResponse
            (
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                "malformed metadata document"
            ), cancellationToken: token);
            
            return;
        }

        var rootCertificates = await _store.GetRootCertificates(token);
        var communityTrustAnchors = await _store.GetAnchorsCertificates(null, token);

        //TODO: null work
        UdapDynamicClientRegistrationValidationResult? result = null;

        try
        {
            // Not in pattern with other validators in IdentityServer.  Typically all errors handled in ValidateAsync...  TODO

            result = await _validator.ValidateAsync(request, communityTrustAnchors, rootCertificates);

            if (result == null)
            {
                throw new NullReferenceException("");
            }
            
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled UdapDynamicClientRegistrationEndpoint Error");
        }

        if (result == null)
        {
            result = new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.MissingValidationResult);
        }

        if (result.IsError)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            
            var error = new UdapDynamicClientRegistrationErrorResponse
            (
                result.Error ?? string.Empty,
                result.ErrorDescription ?? string.Empty
            );
            
            _logger.LogWarning(JsonSerializer.Serialize(error));

            await context.Response.WriteAsJsonAsync(error);

            return;
        }

        // var anchors = (await _store.GetAnchors()).ToList();

        if (result.Client != null)
        {
            var saved = await _store.AddClient(result.Client, token);

            if (saved == 0)
            {
                await context.Response.WriteAsJsonAsync(new UdapDynamicClientRegistrationErrorResponse
                (
                    UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                    "Udap registration failed to save a client."
                ), cancellationToken: token);

                return;
            }
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
            ClientId = result.Client?.ClientId,
            SoftwareStatement = request.SoftwareStatement
        };

        //
        // result.Document is the UdapDynamicClientRegistrationDocument originally sent as the 
        // software_statement and thus all members must be returned as top-level elements.
        //
        if (result.Document != null)
        {
            foreach (var pair in result.Document)
            {
                registrationResponse.Add(pair.Key, pair.Value);
            }
        }

        return registrationResponse;
    }
}