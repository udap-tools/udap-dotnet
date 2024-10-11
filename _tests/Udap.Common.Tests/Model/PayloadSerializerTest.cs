#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using FluentAssertions;
using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using Udap.Model;
using Udap.Model.UdapAuthenticationExtensions;
using Xunit.Abstractions;

namespace Udap.Common.Tests.Model;
public class PayloadSerializerTest
{
    private static readonly JsonSerializerOptions IndentedJsonOptions = new JsonSerializerOptions { WriteIndented = true };
    private readonly ITestOutputHelper _testOutputHelper;

    public PayloadSerializerTest(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public void TestDeserializeExtensionsDictionary()
    {
        //
        // hl7-b2b
        //
        var subjectId = "urn:oid:2.16.840.1.113883.4.6#1234567890";
        var subjectName = "FhirLabs AI calendar prep";
        var subjectRole = "http://nucc.org/provider-taxonomy#207SG0202X";
        var organizationId = new Uri("https://fhirlabs.net/fhir/r4/Organization/99").OriginalString;
        var organizationName = "FhirLabs";

        var b2bHl7 = new HL7B2BAuthorizationExtension()
        {
            SubjectId = subjectId,
            SubjectName = subjectName,
            SubjectRole = subjectRole,
            OrganizationId = organizationId,
            OrganizationName = organizationName
        };

        b2bHl7.PurposeOfUse?.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        b2bHl7.PurposeOfUse?.Add("urn:oid:2.16.840.1.113883.5.9#TREATX");
        b2bHl7.ConsentPolicy?.Add("https://udaped.fhirlabs.net/Policy/Consent/99");
        b2bHl7.ConsentReference?.Add("https://fhirlabs.net/fhir/r4/Consent/99");

        b2bHl7.PurposeOfUse?.Remove("urn:oid:2.16.840.1.113883.5.9#TREATX");

        //
        // hl7-b2b-user
        //
        var userPersonJson = File.ReadAllText("Model/Person-FASTIDUDAPPerson-Example.json");
        var parser = new FhirJsonParser();
        var personResource = parser.Parse<Person>(userPersonJson);
        personResource.Should().NotBeNull();
        var serializer = new FhirJsonSerializer(new SerializerSettings() { Pretty = false });
        var userPerson = serializer.SerializeToString(personResource);
        userPerson.Should().NotBeNullOrEmpty();
        // _testOutputHelper.WriteLine(userPerson);


        JsonElement userPersonElement;
        using (var jasonDocument = JsonDocument.Parse(userPerson))
        {
            userPersonElement = jasonDocument.RootElement.Clone();
        }

        // _testOutputHelper.WriteLine(userPersonElement.GetProperty("text").GetRawText());


        var b2bHl7User = new HL7B2BUserAuthorizationExtension()
        {
            UserPerson = userPersonElement,
        };


        b2bHl7User.PurposeOfUse?.Add("1.3.6.1.2.1.1.3.0#UPTIME");
        b2bHl7User.ConsentPolicy?.Add("https://udaped.fhirlabs.net/Policy/Consent/199");
        b2bHl7User.ConsentReference?.Add("https://fhirlabs.net/fhir/r4/Consent/199");

        var extensions = new Dictionary<string, string>
        {
            { UdapConstants.UdapAuthorizationExtensions.Hl7B2B, b2bHl7.SerializeToJson() },
            { UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER, b2bHl7User.SerializeToJson() }
        };

        var extensionsResult = PayloadSerializer.Deserialize(extensions);

        _testOutputHelper.WriteLine(JsonSerializer.Serialize(extensionsResult, IndentedJsonOptions));

        var b2bHl7Result = ((HL7B2BAuthorizationExtension)extensionsResult[UdapConstants.UdapAuthorizationExtensions.Hl7B2B]);

        b2bHl7Result.Version.Should().BeEquivalentTo(b2bHl7.Version);
        b2bHl7Result.PurposeOfUse.Should().ContainInOrder(b2bHl7.PurposeOfUse);
        b2bHl7Result.ConsentPolicy.Should().ContainInOrder(b2bHl7.ConsentPolicy);


        var b2bHl7UserResult = ((HL7B2BUserAuthorizationExtension)extensionsResult[UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER]);

        b2bHl7UserResult.Version.Should().BeEquivalentTo(b2bHl7User.Version);
        b2bHl7UserResult.PurposeOfUse.Should().ContainInOrder(b2bHl7User.PurposeOfUse);
        b2bHl7UserResult.ConsentPolicy.Should().ContainInOrder(b2bHl7User.ConsentPolicy);
    }
}
