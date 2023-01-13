using System.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Utilities.Encoders;
using Udap.Common.Extensions;

namespace UdapClient.Server.Controllers;

[Route("[controller]")]
[ApiController]
public class MetadataController : ControllerBase
{
    [HttpPost("UploadClientCert")]
    public IActionResult UploadClientCert([FromBody] string base64String)
    {
        HttpContext.Session.SetString("clientCert", base64String);
        
        return Ok();
    }
}
