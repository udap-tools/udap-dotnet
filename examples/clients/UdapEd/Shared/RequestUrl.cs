using Udap.Common.Extensions;
using Udap.Model;

namespace UdapEd.Shared;
public  class RequestUrl
{
    private readonly string _url;

    public RequestUrl(string url)
    {
        _url =url;
    }

    /// <summary>
    /// Utility for UI
    /// Caller will already have formatted string in a {name}={value} format.
    /// </summary>
    /// <param name="queryParameters"></param>
    /// <returns></returns>
    public string AppendParams(params string?[] queryParameters)
    {
        var queryParams = "?";

        foreach (var param in queryParameters)
        {
            if (!string.IsNullOrEmpty(param))
            {
                if (!queryParams.EndsWith('&') && !queryParams.EndsWith('?'))
                {
                    queryParams += "&";
                }

                queryParams += param;
            }
        }

        return _url + queryParams;
    }

    public static string GetWellKnownUdap(string? baseUrl, string? community)
    {
        if (!string.IsNullOrEmpty(community))
        {
            community = $"?community={community}";
        }

        if (!string.IsNullOrEmpty(baseUrl) && !baseUrl.EndsWith(UdapConstants.Discovery.DiscoveryEndpoint, StringComparison.OrdinalIgnoreCase))
        {
            return $"{baseUrl!.EnsureTrailingSlash()}{UdapConstants.Discovery.DiscoveryEndpoint}{community}" ;
        }

        return baseUrl ?? string.Empty ;
    }
}