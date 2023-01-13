using Udap.Model;

namespace UdapClient.Client.Services;

public class UdapClientState
{
    public UdapClientState() {}

    public string MetadataUrl { get; set; } = "https://fhirlabs.net/fhir/r4/.well-known/udap";

    public UdapMetadata? UdapMetadata { get; set; }
    public string ClientCert { get; set; }

    private bool _isLocalStorageInit;

    public bool IsLocalStorageInit()
    {
        return _isLocalStorageInit;
    }

    public void LocalStorageInit()
    {
        _isLocalStorageInit = true;
    }
}

