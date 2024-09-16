#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
using Udap.Common.Extensions;
using Udap.Common.Metadata;
using Udap.Model;

namespace Udap.Metadata.Server;

public class UdapMetaDataEndpoint<TUdapMetadataOptions, TUdapMetadata> 
    where TUdapMetadataOptions : UdapMetadataOptions
    where TUdapMetadata : UdapMetadata
{
    private readonly UdapMetaDataBuilder<TUdapMetadataOptions, TUdapMetadata> _metaDataBuilder;
    private readonly ILogger<UdapMetaDataEndpoint<TUdapMetadataOptions, TUdapMetadata>> _logger;

    public UdapMetaDataEndpoint(UdapMetaDataBuilder<TUdapMetadataOptions, TUdapMetadata> metaDataBuilder, ILogger<UdapMetaDataEndpoint<TUdapMetadataOptions, TUdapMetadata>> logger)
    {
        _metaDataBuilder = metaDataBuilder;
        _logger = logger;
    }

    public async Task<IResult?> Process(HttpContext httpContext, string? community, CancellationToken token)
    {
        return await _metaDataBuilder.SignMetaData(
                httpContext.Request.GetDisplayUrl().GetBaseUrlFromMetadataUrl(),
                community, 
                token)
            is { } udapMetadata
            ? Results.Ok(udapMetadata)
            : Results.NotFound();
    }

    
    public IResult GetCommunities()
    {
        return Results.Ok(_metaDataBuilder.GetCommunities());
    }

    public IResult GetCommunitiesAsHtml(HttpContext httpContext)
    {
        var html = _metaDataBuilder.GetCommunitiesAsHtml(httpContext.Request.GetDisplayUrl().GetBaseUrlFromMetadataUrl());
        httpContext.Response.ContentType = "text/html";
        
        return Results.Content(html);
    }
}