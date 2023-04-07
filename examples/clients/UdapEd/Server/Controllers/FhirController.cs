#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
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
    private readonly FhirClientForDI _fhirClient;
    private readonly ILogger<RegisterController> _logger;

    public FhirController(FhirClientForDI fhirClient, ILogger<RegisterController> logger)
    {
        _fhirClient = fhirClient;
        _logger = logger;
    }

    [HttpPost("SearchForPatient")]
    public async Task<IActionResult> SearchForPatient([FromBody] PatientSearchModel model)
    {
        var searchParams = new SearchParams();
        var patientQuery = model.PatientQuery;

        if (!string.IsNullOrEmpty(patientQuery.Id))
        {
            searchParams.Add("_id", patientQuery.Id);
        }

        if (!string.IsNullOrEmpty(patientQuery.Identifier))
        {
            searchParams.Add("identifier", patientQuery.Identifier);
        }

        if (!string.IsNullOrEmpty(patientQuery.Family))
        {
            searchParams.Add("family", patientQuery.Family);
        }

        if (!string.IsNullOrEmpty(patientQuery.Given))
        {
            searchParams.Add("given", patientQuery.Given);
        }

        if (!string.IsNullOrEmpty(patientQuery.Name))
        {
            searchParams.Add("name", patientQuery.Name);
        }

        if (patientQuery.BirthDate.HasValue)
        {
            searchParams.Add("birthdate", patientQuery.BirthDate.Value.ToString("yyyy-MM-dd"));
        }

        try
        {
            var bundle = await _fhirClient.SearchAsync<Patient>(searchParams);
            var bundleJson = await new FhirJsonSerializer().SerializeToStringAsync(bundle);
            return Ok(bundleJson);
        }
        catch (FhirOperationException ex)
        {
            _logger.LogWarning(ex.Message);
            var outcomeJson = await new FhirJsonSerializer().SerializeToStringAsync(ex.Outcome);

            if (ex.Status == HttpStatusCode.Unauthorized)
            {
                return Unauthorized();
            }

            return NotFound(outcomeJson);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex.Message);
            throw;
        }
    }
}
