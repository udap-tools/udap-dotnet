#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Xunit.Abstractions;

namespace Udap.PKI.Generator;
public class CertificateRenewal : CertificateBase
{
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
