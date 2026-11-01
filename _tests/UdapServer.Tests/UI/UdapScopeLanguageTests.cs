#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.UI.Services;
using Xunit;

namespace UdapServer.Tests.UI;

/// <summary>Plain-language consent wording for scopes.</summary>
public class UdapScopeLanguageTests
{
    /// <summary>Common SMART resource types a FHIR server's scope catalog carries.</summary>
    private static readonly string[] CatalogTypes =
    [
        "AllergyIntolerance", "Condition", "Consent", "Coverage", "Encounter", "Immunization", "List", "Medication",
        "MedicationDispense", "MedicationRequest", "Observation", "Organization", "Patient", "Practitioner", "Procedure", "Provenance"
    ];

    [Fact]
    public void EveryCatalogScope_HasPlainWording()
    {
        foreach (var type in CatalogTypes)
        foreach (var context in new[] { "patient", "user", "system" })
        foreach (var perm in new[] { "read", "rs", "r", "s", "cruds" })
        {
            var scope = $"{context}/{type}.{perm}";
            var wording = UdapScopeLanguage.Describe(scope);
            Assert.True(wording.Known, scope);
            Assert.DoesNotContain("/", wording.Title);
            Assert.DoesNotContain(".", wording.Title);
            Assert.False(wording.Title.EndsWith(" records"), $"{scope} should have its own wording, not the generic fallback");
        }
    }

    [Theory]
    [InlineData("openid")]
    [InlineData("profile")]
    [InlineData("email")]
    [InlineData("fhirUser")]
    [InlineData("launch")]
    [InlineData("launch/patient")]
    [InlineData("offline_access")]
    [InlineData("udap")]
    [InlineData("patient/Patient.rs")]
    [InlineData("user/Patient.read")]
    [InlineData("system/Patient.read")]
    public void CommonScopes_AreKnown(string scope)
    {
        Assert.True(UdapScopeLanguage.Describe(scope).Known);
    }

    [Fact]
    public void ReadOnlyPatientScope_SaysLookAtAndSearch_AndIsNotFlagged()
    {
        var wording = UdapScopeLanguage.Describe("patient/MedicationDispense.rs");

        Assert.Equal("Your filled prescriptions", wording.Title);
        Assert.Equal("The app can look at and search the medicines pharmacies have filled for you.", wording.Detail);
        Assert.False(wording.AllowsChanges);
        Assert.False(wording.BeyondYou);
        Assert.Equal("patient context, MedicationDispense, read and search (SMART v2 .rs)", wording.Technical);
    }

    [Theory]
    [InlineData("patient/Condition.cruds", "look at, search, add to, change and delete")]
    [InlineData("patient/Condition.cud", "add to, change and delete")]
    [InlineData("patient/Condition.write", "add to and change")]
    public void ScopesThatChangeRecords_SaySo(string scope, string verbs)
    {
        var wording = UdapScopeLanguage.Describe(scope);

        Assert.True(wording.AllowsChanges);
        Assert.StartsWith($"The app can {verbs} ", wording.Detail);
    }

    [Theory]
    [InlineData("user/Patient.rs", "not only your own")]
    [InlineData("system/Patient.read", "not limited to your records")]
    public void ScopesBeyondThePatient_SaySo(string scope, string phrase)
    {
        var wording = UdapScopeLanguage.Describe(scope);

        Assert.True(wording.BeyondYou);
        Assert.Contains(phrase, wording.Detail);
    }

    [Fact]
    public void UnlistedResourceType_FallsBackToItsWords()
    {
        var wording = UdapScopeLanguage.Describe("patient/NutritionOrder.rs");

        Assert.True(wording.Known);
        Assert.Equal("Your nutrition order records", wording.Title);
    }

    [Fact]
    public void UnrecognizedScope_IsMarkedUnknown_AndKeepsTheRawValue()
    {
        var wording = UdapScopeLanguage.Describe("vendor:special");

        Assert.False(wording.Known);
        Assert.Equal("vendor:special", wording.Title);
    }
}
