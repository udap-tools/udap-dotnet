#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;

namespace UdapEd.Shared.Model;
public class ResultModel<T>
{
    public ResultModel(){}

    public ResultModel(T result, HttpStatusCode httpStatusCode, Version version)
    {
        this.HttpStatusCode = httpStatusCode;
        this.Version = version;
        Result = result;
    }

    public ResultModel(string errorMessage, HttpStatusCode httpStatusCode, Version version)
    {
        ErrorMessage = errorMessage;
        HttpStatusCode = httpStatusCode;
        Version = version;
    }

    public ResultModel(string errorMessage)
    {
        ErrorMessage = errorMessage;
    }

    public T? Result { get; set; }

    public string? ErrorMessage { get; set; }

    public HttpStatusCode HttpStatusCode { get; set; }

    public Version? Version { get; set; } = default!;
}
