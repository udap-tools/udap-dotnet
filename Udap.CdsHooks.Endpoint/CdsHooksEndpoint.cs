#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using Hl7.Fhir.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.CdsHooks.Model;
using Task = System.Threading.Tasks.Task;

namespace Udap.CdsHooks.Endpoint;

/// <summary>
/// See <a href="https://cds-hooks.org/quickstart/#endpoint-for-discovery">CDS Hooks Endpoint for discovery</a>
/// </summary>
public class CdsHooksEndpoint
{
    private readonly IOptionsMonitor<CdsServices>? _cdsService;
    private readonly ILogger<CdsHooksEndpoint> _logger;
    private JsonSerializerOptions jsonSerializerOptions = new JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new FhirResourceConverter() }
    };

    public CdsHooksEndpoint(IOptionsMonitor<CdsServices>? cdsService, ILogger<CdsHooksEndpoint> logger)
    {
        _cdsService = cdsService;
        _logger = logger;
    }

    public Task<IResult> Process()
    {
        if (_cdsService == null)
        {
            return Task.FromResult(Results.NotFound());
        }   

        return Task.FromResult(Results.Ok(_cdsService.CurrentValue));
    }

    public async Task<IResult> ProcessPost(HttpRequest request)
    {
        if (_cdsService == null)
        {
            return Results.NotFound();
        }

        // Read the request body
        using var reader = new StreamReader(request.Body);
        var requestBody = await reader.ReadToEndAsync();

        // Deserialize the request body to a JSON object
        var cdsRequest = JsonSerializer.Deserialize<CdsRequest>(requestBody, jsonSerializerOptions);

        // Serialize it back with indentation
        var indentedJson = JsonSerializer.Serialize(cdsRequest, new JsonSerializerOptions { WriteIndented = true });

        // Log the indented JSON
        _logger.LogDebug(indentedJson);
        // Process the request body as needed
        // For example, you might deserialize it to a specific model
        // var model = JsonSerializer.Deserialize<YourModel>(requestBody);

        // Return an appropriate response
        var patient = cdsRequest?.Prefetch?["patient"] as Patient;
        
        var card = new CdsCard()
        {
            Uuid = Guid.NewGuid().ToString(),
            Summary = "Patient Greeting",
            Indicator = "info",
            Detail = $"Hello, {patient?.Name[0].Given.First()}",
            Source = new CdsSource()
            {
                Label = "UDAP CDS Service",
                Url = new Uri("https://fhirlabs.net/fhir/r4")
            }
            
        };

        var response = new CdsResponse()
        {
            Cards = new List<CdsCard> { card }
        };

        return Results.Ok(response);
    }
}