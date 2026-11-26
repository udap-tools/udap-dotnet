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
    private readonly IUdapDynamicClientRegistrationProcessor _processor;
    private readonly IUdapClientRegistrationStore _store;
    private readonly IEnumerable<ICommunityRegistrationValidator> _communityRegistrationValidators;
    private readonly ILogger<UdapDynamicClientRegistrationEndpoint> _logger;

    public UdapDynamicClientRegistrationEndpoint(
        IUdapDynamicClientRegistrationValidator validator,
        IUdapDynamicClientRegistrationProcessor processor,
        IUdapClientRegistrationStore store,
        IEnumerable<ICommunityRegistrationValidator> communityRegistrationValidators,
        ILogger<UdapDynamicClientRegistrationEndpoint> logger)
    {
        _validator = validator;
        _processor = processor;
        _store = store;
        _communityRegistrationValidators = communityRegistrationValidators;
        _logger = logger;
    }

    /// <summary>
    /// Initiate UDAP Dynamic Client Registration for <see cref="UdapDynamicClientRegistrationEndpoint"/>
    /// </summary>
    /// <param name="httpContext"></param>
    /// <param name="token"></param>
    /// <returns></returns>
    public async Task Process(HttpContext httpContext, CancellationToken token)
    {
        //
        // Can't tell if this is truly required from specifications.
        // Maybe search the DCR RFC's
        // National Directory client seems to be missing this header.
        // Maybe discuss this at the next UDAP meeting.
        //
        if (!httpContext.Request.HasJsonContentType())
        {
            _logger.LogDebug("Registration rejected: unsupported Content-Type {ContentType}",
                httpContext.Request.ContentType?.Replace("\r", string.Empty).Replace("\n", string.Empty));
            httpContext.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
            return;
        }

        UdapRegisterRequest request;
        try
        {
            request = await httpContext.Request.ReadFromJsonAsync<UdapRegisterRequest>(cancellationToken: token)
                      ?? throw new ArgumentNullException(nameof(httpContext.Request));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, UdapDynamicClientRegistrationErrorDescriptions.MalformedMetaDataDocument);

            httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
            await httpContext.Response.WriteAsJsonAsync(new UdapDynamicClientRegistrationErrorResponse
            (
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.MalformedMetaDataDocument
            ), cancellationToken: token);

            return;
        }

        var intermediateCertificates = await _store.GetIntermediateCertificates(token);
        var communityTrustAnchors = await _store.GetAnchorsCertificates(null, token);
        var anchors = await _store.GetAnchors(null, token);

        // Create context
        var context = new UdapDynamicClientRegistrationContext { Request = request };

        //TODO: null work
        UdapDynamicClientRegistrationValidationResult? validationResult = null;

        try
        {
            if (communityTrustAnchors == null)
            {
                throw new NullReferenceException("Missing Community Trust Anchors");
            }

            validationResult = await _validator.ValidateAsync(context, intermediateCertificates, communityTrustAnchors, anchors);

            if (validationResult == null)
            {
                throw new NullReferenceException("Registration validator has not results.");
            }

        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled UdapDynamicClientRegistrationEndpoint Error");
        }

        validationResult ??= new UdapDynamicClientRegistrationValidationResult(
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                UdapDynamicClientRegistrationErrorDescriptions.MissingValidationResult);

        if (validationResult.IsError)
        {
            httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;

            var error = new UdapDynamicClientRegistrationErrorResponse
            (
                validationResult.Error ?? string.Empty,
                validationResult.ErrorDescription ?? string.Empty
            );

            _logger.LogWarning("Error: {@Error}", error);

            await httpContext.Response.WriteAsJsonAsync(error, cancellationToken: token);

            return;
        }

        // Community-specific registration validation
        if (!string.IsNullOrEmpty(context.CommunityName))
        {
            foreach (var communityValidator in _communityRegistrationValidators)
            {
                if (communityValidator.AppliesToCommunity(context.CommunityName))
                {
                    var communityResult = await communityValidator.ValidateAsync(context);
                    if (communityResult is { IsError: true })
                    {
                        httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;

                        var communityError = new UdapDynamicClientRegistrationErrorResponse(
                            communityResult.Error ?? string.Empty,
                            communityResult.ErrorDescription ?? string.Empty);

                        _logger.LogWarning("Error: {@Error}", communityError);

                        await httpContext.Response.WriteAsJsonAsync(communityError, cancellationToken: token);

                        return;
                    }
                }
            }
        }

        // Process (create client + persist)
        try
        {
            var processorResult = await _processor.ProcessAsync(context, token);

            if (processorResult.IsError)
            {
                httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;

                var error = new UdapDynamicClientRegistrationErrorResponse
                (
                    processorResult.Error ?? string.Empty,
                    processorResult.ErrorDescription ?? string.Empty
                );

                _logger.LogWarning("Error: {@Error}", error);

                await httpContext.Response.WriteAsJsonAsync(error, cancellationToken: token);

                return;
            }

            if (processorResult.IsCancellation)
            {
                // From section 6 of https://www.udap.org/udap-dynamic-client-registration.html
                // The Authorization Server SHOULD return an HTTP 200 response code (instead of a 201 response code)
                // for successful registration modification and cancellation requests.
                httpContext.Response.StatusCode = StatusCodes.Status200OK;
            }
            else if (processorResult.IsUpsert)
            {
                // From section 6 of https://www.udap.org/udap-dynamic-client-registration.html
                // The Authorization Server SHOULD return an HTTP 200 response code (instead of a 201 response code)
                // for successful registration modification and cancellation requests.
                httpContext.Response.StatusCode = StatusCodes.Status200OK;
            }
            else
            {
                httpContext.Response.StatusCode = StatusCodes.Status201Created;
            }
        }
        catch (Exception ex)
        {
            await httpContext.Response.WriteAsJsonAsync(new UdapDynamicClientRegistrationErrorResponse
            (
                UdapDynamicClientRegistrationErrors.InvalidClientMetadata,
                "Udap registration failed to save a client."
            ), cancellationToken: token);

            _logger.LogError(ex, "Udap registration failed to save a client.");
            return;
        }

        var registrationResponse = BuildResponseDocument(request, validationResult, context);

        var options = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        await httpContext.Response.WriteAsJsonAsync(registrationResponse, options, "application/json", cancellationToken: token);
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
    private static UdapDynamicClientRegistrationDocument BuildResponseDocument(
        UdapRegisterRequest request,
        UdapDynamicClientRegistrationValidationResult result,
        UdapDynamicClientRegistrationContext context)
    {
        var registrationResponse = new UdapDynamicClientRegistrationDocument()
        {
            ClientId = context.Client?.ClientId,
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
