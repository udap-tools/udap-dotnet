using System.Linq;
using Udap.Metadata.Server;
using Udap.Model;

public static class MyCustomUdapMetadata
{
    public static UdapMetadata Build(UdapConfig udapConfig)
    {
        var udapMetadata = new UdapMetadata(udapConfig);
        
        udapMetadata.UdapAuthorizationExtensionsSupported.Add("acme-ext");

        return udapMetadata;
    }
}