using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Udap.Model;
using UdapEd.Server.Extensions;

namespace UdapEd.Server.Controllers;

[Route("[controller]")]
[EnableRateLimiting(RateLimitExtensions.Policy)]
public class MetadataController : Controller
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<MetadataController> _logger;

    public MetadataController(HttpClient httpClient, ILogger<MetadataController> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> Get([FromQuery] string metadataUrl)
    {
        var response = await _httpClient.GetStringAsync(metadataUrl);
        var result = JsonSerializer.Deserialize<UdapMetadata>(response);

        return Ok(result);
    }
}