#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Udap.Smart.Model;

namespace Udap.Smart.Metadata;

/// <summary>
/// See <a href="https://hl7.org/fhir/smart-app-launch/conformance.html">SMART App Launch: Conformance</a>
/// </summary>
public class SmartMetadataEndpoint
{
    private readonly IOptionsMonitor<SmartMetadata>? _smartMetadata;
    private readonly string? _namedOption;

    public SmartMetadataEndpoint(IOptionsMonitor<SmartMetadata>? smartMetadata, string? namedOption)
    {
        _smartMetadata = smartMetadata;
        _namedOption = namedOption;
    }

    public Task<IResult> Process()
    {
        if (_smartMetadata == null)
        {
            return Task.FromResult(Results.NotFound());
        }   

        return Task.FromResult(Results.Ok(_namedOption == null ? 
            _smartMetadata.CurrentValue : 
            _smartMetadata.Get(_namedOption) ));
    }
}