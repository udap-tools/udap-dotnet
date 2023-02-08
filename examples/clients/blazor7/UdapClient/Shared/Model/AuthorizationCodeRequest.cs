using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UdapClient.Shared.Model;
public class AuthorizationCodeRequest
{
    public string? ResponseType { get; set; }
    public string? State { get; set; }

    public string? ClientId { get; set; }

    public string? Scope { get; set; }

    public string? RedirectUri { get; set; }


}
