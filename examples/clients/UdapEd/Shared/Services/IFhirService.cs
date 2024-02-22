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

namespace UdapEd.Shared.Services;

public interface IFhirService
{
    Task<FhirResultModel<List<Patient>>> SearchPatient(PatientSearchModel model);
    Task<FhirResultModel<Hl7.Fhir.Model.Bundle>> MatchPatient(string parametersJson);
}