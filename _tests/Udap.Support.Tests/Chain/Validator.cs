#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Support.Tests.Chain
{
    public class Validator
    {
        // public bool ValidateCertificateChain(
        //     X509Certificate2 issuedCertificate2, 
        //     X509ChainStatusFlags problemFlags,
        //     IServiceProvider serviceProvider)
        // {
        //     var certStore = serviceProvider.GetService<ICertificateStore>();
        //
        //     var anchors = certStore.Resolve().Anchors
        //         .Where(c => c.Community == _fixture.Community)
        //         .OrderBy(c => c.Certificate.NotBefore)
        //         .Select(c => c.Certificate);
        //
        //     var validator = new TrustChainValidator(new X509ChainPolicy(), problemFlags);
        //     validator.Problem += _diagnosticsChainValidator.OnChainProblem;
        //
        //     // Help while writing tests to see problems summarized.
        //     validator.Error += (certificate2, exception) => _testOutputHelper.WriteLine("Error: " + exception.Message);
        //     validator.Problem += element => _testOutputHelper.WriteLine("Problem: " + element.ChainElementStatus.Summarize(problemFlags));
        //     validator.Untrusted += certificate2 => _testOutputHelper.WriteLine("Untrusted: " + certificate2.Subject);
        //
        //     return validator.IsTrustedCertificate(issuedCertificate2, anchors.ToArray().ToX509Collection());
        // }
    }
}
