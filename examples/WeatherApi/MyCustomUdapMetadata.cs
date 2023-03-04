using System.Collections.Generic;
using Udap.Model;

namespace WeatherApi;

public static class MyCustomUdapMetadata
{
    public static UdapMetadata Build(UdapConfig udapConfig, HashSet<string>? scopes = null)
    {
        var udapMetadata = new UdapMetadata(udapConfig, scopes);
        
        udapMetadata.ScopesSupported.Add("system/Patient.cruds");
        udapMetadata.ScopesSupported.Add("user/AllergyIntolerance.cruds");
        udapMetadata.ScopesSupported.Add("patient/*.cruds");

        udapMetadata.UdapAuthorizationExtensionsSupported.Add("acme-ext");

        return udapMetadata;
    }
}