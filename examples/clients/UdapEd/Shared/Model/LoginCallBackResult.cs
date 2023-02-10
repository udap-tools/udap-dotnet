namespace UdapEd.Shared.Model;
public class LoginCallBackResult
{
    public string? Code { get; set; }

    public string? Scope { get; set; }
   
    public string? State { get; set; }

    public string? SessionState { get; set; }

    public string? Issuer { get; set; }
}
