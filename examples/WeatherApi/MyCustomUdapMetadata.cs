using System.Collections.Generic;
using Udap.Model;

namespace WeatherApi;

public static class MyCustomUdapMetadata
{
    public static UdapMetadata Build(UdapConfig udapConfig, HashSet<string>? scopes = null)
    {
        var udapMetadata = new UdapMetadata(udapConfig, scopes);
        
        udapMetadata.UdapAuthorizationExtensionsSupported.Add("acme-ext");

        return udapMetadata;
    }
}