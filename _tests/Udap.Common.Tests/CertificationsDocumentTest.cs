#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using Udap.Model.Registration;
using Xunit.Abstractions;
using Task = System.Threading.Tasks.Task;

namespace Udap.Common.Tests
{
    public class CertificationsDocumentTest
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public CertificationsDocumentTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void UdapCertificationAndEndorsementDocument_SerializationTest()
        {
            UdapCertificationAndEndorsementDocument document = new UdapCertificationAndEndorsementDocument("Test Certification");
            document.Issuer = "joe";
            document.Subject = "joe";

            _testOutputHelper.WriteLine(document.SerializeToJson());
        }

        [Fact]
        public async Task TestParametersResource()
        {
            var parametersJson = "{\"resourceType\":\"Parameters\",\"parameter\":[{\"name\":\"UdapEdPatientMatch\",\"resource\":{\"resourceType\":\"Patient\",\"birthDate\":\"1970-05-01\"}}]}";
            var parametersResource = await new FhirJsonParser().ParseAsync<Parameters>(parametersJson);
            
            _testOutputHelper.WriteLine(new FhirJsonSerializer().SerializeToString(parametersResource.Parameter.Single(n => n.Name == "UdapEdPatientMatch").Resource));

            var patient = parametersResource.Parameter.Single(n => n.Name == "UdapEdPatientMatch").Resource as Patient;
            Assert.Equal("1970-05-01", patient.BirthDate);

            var patientJson = await new FhirJsonSerializer().SerializeToStringAsync(parametersResource.Parameter
                .Single(n => n.Name == "UdapEdPatientMatch").Resource);
            patient = await new FhirJsonParser().ParseAsync<Patient>(patientJson);
            Assert.Equal("1970-05-01", patient.BirthDate);
            
            _testOutputHelper.WriteLine(await new FhirJsonSerializer(new SerializerSettings{Pretty = true}).SerializeToStringAsync(parametersResource));
        }
    }
}