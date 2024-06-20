using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Xunit.Abstractions;

namespace Udap.PKI.Generator;
public class CertificateRenewal : CertificateBase
{
    private readonly ITestOutputHelper _testOutputHelper;


    //
    // Community:SureFhirLabs:: Certificate Store File Constants
    //
    private static string SureFhirLabsCertStore
    {
        get
        {
            var baseDir = BaseDir;

            return $"{baseDir}/certstores/surefhirlabs_community";
        }
    }

    private static string SurefhirlabsUdapIntermediates { get; } = $"{SureFhirLabsCertStore}/intermediates";
    private static string SurefhirlabsUdapIntermediatesRenewed { get; } = $"{SureFhirLabsCertStore}/intermediates/renewed";

    [Fact(Skip = "Experimenting")]
    public void RenewIntermediateCertificate()
    {
        using var rootCA = new X509Certificate2($"{SureFhirLabsCertStore}/SureFhirLabs_CA.pfx", "udap-test");
        using var subCA = new X509Certificate2($"{SurefhirlabsUdapIntermediates}/SureFhirLabs_Intermediate.pfx", "udap-test");



        //SurefhirlabsUdapIntermediatesRenewed
    }
}
