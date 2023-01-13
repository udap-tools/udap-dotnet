using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;
using Udap.Model;

namespace UdapClient.Client.Services;

public class UdapClientState
{
    public UdapClientState() {}

    public string MetadataUrl { get; set; } = "https://fhirlabs.net/fhir/r4/.well-known/udap";

    public UdapMetadata? UdapMetadata { get; set; }
    public string ClientCert { get; set; }


    private byte[] _clientCert;
    private bool _isLocalStorageInit;

    public bool IsLocalStorageInit()
    {
        return _isLocalStorageInit;
    }

    public void LocalStorageInit()
    {
        _isLocalStorageInit = true;
    }

    public void SetClientP12Cert(byte[] bytes)
    {
        _clientCert = bytes;
    }

    public X509Certificate2 GetClientP12Cert(SecureString password)
    {
        return new X509Certificate2(_clientCert);
    }
}

