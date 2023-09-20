#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Text.Json;
using Hl7.Fhir.Model;
using Hl7.Fhir.Rest;
using Hl7.Fhir.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Udap.Client.Rest;
using UdapEd.Server.Extensions;
using UdapEd.Shared;
using UdapEd.Shared.Model;

namespace UdapEd.Server.Controllers;
[Route("[controller]")]
[EnableRateLimiting(RateLimitExtensions.Policy)]
public class FhirController : ControllerBase
{
    private readonly FhirClientWithUrlProvider _fhirClient;
    private readonly ILogger<RegisterController> _logger;

    public FhirController(FhirClientWithUrlProvider fhirClient, ILogger<RegisterController> logger)
    {
        _fhirClient = fhirClient;
        _logger = logger;
    }

    [HttpPost("SearchForPatient")]
    public async Task<IActionResult> SearchForPatient([FromBody] PatientSearchModel model)
    {
        var searchParams = new SearchParams();

        if (!string.IsNullOrEmpty(model.Id))
        {
            searchParams.Add("_id", model.Id);
        }

        if (!string.IsNullOrEmpty(model.Identifier))
        {
            searchParams.Add("identifier", model.Identifier);
        }

        if (!string.IsNullOrEmpty(model.Family))
        {
            searchParams.Add("family", model.Family);
        }

        if (!string.IsNullOrEmpty(model.Given))
        {
            searchParams.Add("given", model.Given);
        }

        if (!string.IsNullOrEmpty(model.Name))
        {
            searchParams.Add("name", model.Name);
        }

        if (model.BirthDate.HasValue)
        {
            searchParams.Add("birthdate", model.BirthDate.Value.ToString("yyyy-MM-dd"));
        }

        try
        {
            if (model.GetResource)
            {
                _fhirClient.Settings.PreferredFormat = ResourceFormat.Json;
                var patient = await _fhirClient.ReadAsync<Patient>($"Patient/{model.Id}");
                var patientJson = await new FhirJsonSerializer().SerializeToStringAsync(patient);
                return Ok(patientJson);
            }

            _fhirClient.Settings.PreferredFormat = ResourceFormat.Json;
            var bundle = await _fhirClient.SearchAsync<Patient>(searchParams);
            var bundleJson = await new FhirJsonSerializer().SerializeToStringAsync(bundle);
            return Ok(bundleJson);
        }
        catch (FhirOperationException ex)
        {
            _logger.LogWarning(ex.Message);

            if (ex.Status == HttpStatusCode.Unauthorized)
            {
                return Unauthorized();
            }

            if (ex.Outcome != null)
            {
                var outcomeJson = await new FhirJsonSerializer().SerializeToStringAsync(ex.Outcome);
                return NotFound(outcomeJson);
            }
            else
            {
                return NotFound("Resource Server Error: " + ex.Message);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex.Message);
            throw;
        }
    }

    [HttpPost("MatchPatient")]
    public async Task<IActionResult> MatchPatient([FromBody] string parametersJson)
    {
        try
        {
            var parametersResource = await new FhirJsonParser().ParseAsync<Parameters>(parametersJson);
            var bundle = await _fhirClient.TypeOperationAsync<Patient>("match", parametersResource);
            var bundleJson = await new FhirJsonSerializer().SerializeToStringAsync(bundle);

            return Ok(bundleJson);
        }
        catch (FhirOperationException ex)
        {
            _logger.LogWarning(ex.Message);

            if (ex.Status == HttpStatusCode.Unauthorized)
            {
                return Unauthorized();
            }

            if(ex.Outcome != null)
            {
                var outcomeJson = await new FhirJsonSerializer().SerializeToStringAsync(ex.Outcome);
                return NotFound(outcomeJson);
            }
            else
            {
                return NotFound("Resource Server Error: " + ex.Message);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex.Message);
            throw;
        }
    }
}
