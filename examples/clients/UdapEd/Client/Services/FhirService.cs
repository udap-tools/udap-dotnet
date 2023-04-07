#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Http.Json;
using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using UdapEd.Shared.Model;

namespace UdapEd.Client.Services;

public class FhirService
{
    readonly HttpClient _httpClient;

    public FhirService(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }
    
    public async Task<FhirResultModel<List<Patient>>> SearchPatient(PatientSearchModel model)
    {
        var response = await _httpClient.PostAsJsonAsync("Fhir/SearchForPatient", model);

        if (response.IsSuccessStatusCode)
        {
            var result = await response.Content.ReadAsStringAsync();
            var bundle = new FhirJsonParser().Parse<Bundle>(result);
            var patients = bundle.Entry.Select(e => e.Resource as Patient).ToList();

            return new FhirResultModel<List<Patient>>(patients);
        }

        if(response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return new FhirResultModel<List<Patient>>(true);
        }

        if (response.StatusCode == HttpStatusCode.InternalServerError)
        {
            var result = await response.Content.ReadAsStringAsync();

            if (result.Contains(nameof(UriFormatException)))
            {
                var operationOutCome = new OperationOutcome()
                {
                    ResourceBase = null
                };

                return new FhirResultModel<List<Patient>>(operationOutCome, HttpStatusCode.PreconditionFailed);
            }
        }

        {
            var result = await response.Content.ReadAsStringAsync();
            var operationOutcome = new FhirJsonParser().Parse<OperationOutcome>(result);

            return new FhirResultModel<List<Patient>>(operationOutcome, response.StatusCode);
        }
    }
}