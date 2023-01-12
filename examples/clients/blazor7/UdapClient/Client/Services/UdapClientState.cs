namespace UdapClient.Client.Services;

public class UdapClientState
{
    public UdapClientState(){}

    public string MetadataUrl { get; set; }

    public string RegistrationEndPoint { get; set; } = "https://fhirlabs.net/fhir/r4/.well-known/udap";
}
