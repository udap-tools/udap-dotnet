#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using Hl7.Fhir.Model;

namespace UdapEd.Shared.Model;
public class FhirResultModel<T>
{
    public FhirResultModel(T result, HttpStatusCode httpStatusCode, Version version)
    {
        Result = result;
        this.HttpStatusCode = httpStatusCode;
        this.Version = version;
    }

    public FhirResultModel(OperationOutcome? operationOutCome, HttpStatusCode httpStatusCode, Version version)
    {
        this.OperationOutCome = operationOutCome;
        this.HttpStatusCode = httpStatusCode;
        this.Version = version;
    }

    public FhirResultModel(bool unAuthorized)
    {
        UnAuthorized = unAuthorized;
    }

    public OperationOutcome? OperationOutCome { get; }

    public T? Result { get; }
    
    public bool UnAuthorized { get; }

    public HttpStatusCode? HttpStatusCode { get; }

    public Version? Version { get; }
}
