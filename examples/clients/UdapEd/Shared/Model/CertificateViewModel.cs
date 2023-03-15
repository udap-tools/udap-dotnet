using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UdapEd.Shared.Model;
public  class CertificateViewModel
{
    /// <summary>
    /// Disect certificate into most used properties
    /// </summary>
    public List<Dictionary<string, string>> TableDisplay { get; set; } = new List<Dictionary<string, string>>();

    /// <summary>
    /// OpenSSL or CertUtil verbose display
    /// </summary>
    public string PlatformToolDisplay { get; set; }
}
