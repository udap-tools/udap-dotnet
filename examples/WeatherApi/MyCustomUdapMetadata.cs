using System.Collections.Generic;
using Udap.Model;

namespace WeatherApi;

public static class MyCustomUdapMetadata
{
    public static UdapMetadata Build(UdapMetadataOptions udapMetadataOptions, HashSet<string>? scopes = null)
    {
        var udapMetadata = new UdapMetadata(udapMetadataOptions, scopes);
        
        udapMetadata.ScopesSupported.Add("system/Patient.cruds");
        udapMetadata.ScopesSupported.Add("user/AllergyIntolerance.cruds");
        udapMetadata.ScopesSupported.Add("patient/*.cruds");

        udapMetadata.UdapAuthorizationExtensionsSupported.Add("acme-ext");

        return udapMetadata;
    }
}