#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Hl7.Fhir.Model;
using System.Text.Json;
using Udap.CdsHooks.Model;
using Xunit.Abstractions;

namespace Udap.Common.Tests.CdsHooks;
public class Experimental
{
    private readonly ITestOutputHelper _testOutputHelper;

    public Experimental(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public void TestCdsRequestDeserialize()
    {
        var json = File.ReadAllText("CdsHooks/CdsRequest.json");
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new FhirResourceConverter() }
        };

        var cdsRequest = JsonSerializer.Deserialize<CdsRequest>(json, options);

        var patient = cdsRequest?.Prefetch?["patient"] as Patient;

        _testOutputHelper.WriteLine(patient?.Name[0].Given.First());
    }
}
