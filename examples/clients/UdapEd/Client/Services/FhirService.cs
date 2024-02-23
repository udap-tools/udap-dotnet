#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using UdapEd.Shared.Model;
using UdapEd.Shared.Services;

namespace UdapEd.Client.Services;

public class FhirService : IFhirService
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
            if (model.GetResource)
            {
                var patient = new FhirJsonParser().Parse<Patient>(result);
                return new FhirResultModel<List<Patient>>(new List<Patient> { patient }, response.StatusCode, response.Version);
            }

            var bundle = new FhirJsonParser().Parse<Bundle>(result);
            var operationOutcome = bundle.Entry.Select(e => e.Resource as OperationOutcome).ToList();
            
            if (operationOutcome.Any(o => o != null))
            {
                return new FhirResultModel<List<Patient>>(operationOutcome.First(), response.StatusCode, response.Version);
            }

            var patients = bundle.Entry.Select(e => e.Resource as Patient).ToList();

            return new FhirResultModel<List<Patient>>(patients, response.StatusCode, response.Version);
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

                return new FhirResultModel<List<Patient>>(operationOutCome, HttpStatusCode.PreconditionFailed, response.Version);
            }
        }
        //todo constant :: and this whole routine is ugly.  Should move logic upstream to controller
        //This code exists from testing various FHIR servers like MEDITECH.
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            var result = await response.Content.ReadAsStringAsync();
            if (result.Contains("Resource Server Error:"))
            {
                var operationOutCome = new OperationOutcome()
                {
                    ResourceBase = null,
                    Issue = new List<OperationOutcome.IssueComponent>
                    {
                        new OperationOutcome.IssueComponent
                        {
                            Diagnostics = result
                        }
                    }
                };

                return new FhirResultModel<List<Patient>>(operationOutCome, HttpStatusCode.InternalServerError,
                    response.Version);
            }
        }

        {
            var result = await response.Content.ReadAsStringAsync();
            var operationOutcome = new FhirJsonParser().Parse<OperationOutcome>(result);

            return new FhirResultModel<List<Patient>>(operationOutcome, response.StatusCode, response.Version);
        }
    }

    public async Task<FhirResultModel<Bundle>> MatchPatient(string parametersJson)
    {
        var parameters = await new FhirJsonParser().ParseAsync<Parameters>(parametersJson);
        var json = await new FhirJsonSerializer().SerializeToStringAsync(parameters); // removing line feeds
        var jsonMessage = JsonSerializer.Serialize(json); // needs to be json
        var content = new StringContent(jsonMessage, Encoding.UTF8, new MediaTypeHeaderValue("application/json"));
        var response = await _httpClient.PostAsync("Fhir/MatchPatient", content);

        if (response.IsSuccessStatusCode)
        {
            var result = await response.Content.ReadAsStringAsync();
            var bundle = new FhirJsonParser().Parse<Bundle>(result);
            // var patients = bundle.Entry.Select(e => e.Resource as Patient).ToList();

            return new FhirResultModel<Bundle>(bundle, response.StatusCode, response.Version);
        }
        
        Console.WriteLine(response.StatusCode);
        
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return new FhirResultModel<Bundle>(true);
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

                return new FhirResultModel<Bundle>(operationOutCome, HttpStatusCode.PreconditionFailed, response.Version);
            }
        }

        //todo constant :: and this whole routine is ugly.  Should move logic upstream to controller
        //This code exists from testing various FHIR servers like MEDITECH.
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            var result = await response.Content.ReadAsStringAsync();
            if (result.Contains("Resource Server Error:"))
            {
                var operationOutCome = new OperationOutcome()
                {
                    ResourceBase = null,
                    Issue = new List<OperationOutcome.IssueComponent>
                    {
                        new OperationOutcome.IssueComponent
                        {
                            Diagnostics = result
                        }
                    }
                };

                return new FhirResultModel<Bundle>(operationOutCome, HttpStatusCode.InternalServerError,
                    response.Version);
            }
        }

        {
            var result = await response.Content.ReadAsStringAsync();
            var operationOutcome = new FhirJsonParser().Parse<OperationOutcome>(result);

            return new FhirResultModel<Bundle>(operationOutcome, response.StatusCode, response.Version);
        }
    }
}