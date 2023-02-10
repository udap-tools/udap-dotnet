namespace UdapEd.Shared.Model;
public class ClientStatus
{
    public ClientStatus(bool isValid, string statusMessage)
    {
        IsValid = isValid;
        StatusMessage = statusMessage;
    }

    public bool IsValid { get; set; }

    public string StatusMessage { get; set; }
}
