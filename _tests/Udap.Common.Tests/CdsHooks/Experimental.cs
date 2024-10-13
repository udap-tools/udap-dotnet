#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using System.Text.Json;
using System.Text.Json.Serialization;
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
            WriteIndented = true,
            Converters = { new FhirResourceConverter() },
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        var cdsRequest = JsonSerializer.Deserialize<CdsRequest>(json, options);
        var serializedCdsRequest = JsonSerializer.Serialize(cdsRequest, options);

        _testOutputHelper.WriteLine(serializedCdsRequest);
    }
}