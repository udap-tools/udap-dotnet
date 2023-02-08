using System.Text.Encodings.Web;

namespace UdapClient.Shared;
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
}
