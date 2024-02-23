#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Hl7.Fhir.Model;
using UdapEd.Shared.Model;
using UdapEd.Shared.Services;

namespace UdapEdAppMaui.Services;
internal class FhirService : IFhirService
{
    readonly HttpClient _httpClient;

    public FhirService(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public Task<FhirResultModel<List<Patient>>> SearchPatient(PatientSearchModel model)
    {
        throw new NotImplementedException();
    }

    public Task<FhirResultModel<Bundle>> MatchPatient(string parametersJson)
    {
        throw new NotImplementedException();
    }
}
