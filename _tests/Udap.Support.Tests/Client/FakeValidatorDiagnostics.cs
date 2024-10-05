#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Udap.Common.Certificates;

namespace Udap.Support.Tests.Client;
public class FakeValidatorDiagnostics
{
    public bool ProblemCalled;
    public bool ErrorCalled;
    public bool UntrustedCalled;
    public bool TokenErrorCalled;

    public string UnTrustedCertificate = string.Empty;

    private readonly List<string> _actualErrorMessages = [];
    public List<string> ActualErrorMessages
    {
        get { return _actualErrorMessages; }
    }

    public void OnChainProblem(X509ChainElement chainElement)
    {
        foreach (var chainElementStatus in chainElement.ChainElementStatus
                     .Where(s => (s.Status & TrustChainValidator.DefaultProblemFlags) != 0))
        {
            var problem = $"Trust ERROR ({chainElementStatus.Status}){chainElementStatus.StatusInformation}, {chainElement.Certificate}";
            _actualErrorMessages.Add(problem);
            ProblemCalled = true;
        }
    }

    public void OnError(X509Certificate2 certificate, Exception exception)
    {
        _actualErrorMessages.Add($"Failed validating certificate: {certificate.SubjectName.Name} \n {exception.Message}");
        ErrorCalled = true;
    }

    public void OnUnTrusted(X509Certificate2 certificate)
    {
        UnTrustedCertificate = certificate.SubjectName.Name;
        _actualErrorMessages.Add($"Untrusted validating certificate: {certificate.SubjectName.Name}");
        UntrustedCalled = true;
    }

    public void OnTokenError(string message)
    {
        _actualErrorMessages.Add($"Failed JWT Validation: {message}");
        TokenErrorCalled = true;
    }
}
