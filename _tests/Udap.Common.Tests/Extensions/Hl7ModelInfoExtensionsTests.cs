#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using FluentAssertions;
using Udap.Common.Extensions;

namespace Udap.Common.Tests.Extensions;
public class Hl7ModelInfoExtensionsTests
{
    Func<string, bool> treatmentSpecification = r => r is "Patient" or "AllergyIntolerance" or "Condition" or "Encounter";

    [Fact]
    public void Test()
    {
        Hl7ModelInfoExtensions.BuildHl7FhirV1Scopes(new List<string>() { "patient", "user" }, treatmentSpecification)
            .Should().Contain("patient/Patient.read");

        Hl7ModelInfoExtensions.BuildHl7FhirV2Scopes(new List<string>() { "patient", "user" }, treatmentSpecification)
            .Should().Contain("patient/Patient.r").And.Contain("patient/Patient.rs");

        Hl7ModelInfoExtensions.BuildHl7FhirV2Scopes(new List<string>() { "patient", "user" }, treatmentSpecification, "cruds")
            .Should().Contain("patient/Patient.cruds").And.Contain("patient/Patient.rs");

        Hl7ModelInfoExtensions.BuildHl7FhirV1AndV2Scopes(new List<string>() { "patient", "user" }, treatmentSpecification, "read", "cruds")
            .Should().Contain("patient/Patient.cruds").And.Contain("patient/Patient.rs").And.Contain("patient/Patient.read").And
            .Contain("user/Patient.cruds").And.Contain("user/Patient.rs").And.Contain("user/Patient.read");

        Hl7ModelInfoExtensions.BuildHl7FhirV1AndV2Scopes("user", treatmentSpecification, "read", "cruds")
            .Should().Contain("user/Patient.cruds").And.Contain("user/Patient.rs").And.Contain("user/Patient.read");

    }
}
