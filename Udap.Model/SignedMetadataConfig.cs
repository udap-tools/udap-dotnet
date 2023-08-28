using System;
using System.Collections.Generic;

namespace Udap.Model;

/// <summary>
/// Model for constructing the signed_endpoints metadata element.
/// See <a href="https://www.udap.org/udap-server-metadata.html"/> section 1 and 2.
/// </summary>
public class SignedMetadataConfig
{
    private TimeSpan _expirationTimeSpan = new TimeSpan(0, 5, 0);

    public List<string> RegistrationSigningAlgorithms { get; set; } = new List<string>();
    public List<string> TokenSigningAlgorithms { get; set; } = new List<string>();

    public string Issuer { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;

    /// <summary>
    /// The expiration timespan SHALL be no more than 5 minutes after the value of
    /// issued (iat) time. 
    /// </summary>
    /// <remarks>Defaults to 5 minutes.  While in development mode the limit is not enforced.</remarks>
    public TimeSpan ExpirationTimeSpan
    {
        get => _expirationTimeSpan;
        set
        {
            if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") != "Development" &&
                value > TimeSpan.FromMinutes(5))
            {
                throw new ArgumentException(
                    $"{nameof(ExpirationTimeSpan)} SHALL be no more than 5 minutes after the value of the iat claim");
            }

            _expirationTimeSpan = value;
        }
    }

    public string AuthorizationEndpoint { get; set; } = string.Empty;

    public string TokenEndpoint { get; set; } = string.Empty;

    public string RegistrationEndpoint { get; set; } = string.Empty;

}

public static class DefaultAlgorithms
{
    public static List<string> RsaTokenSigningAlgorithms { get; } = new List<string>
    {
        "RS256",
        "RS384"
    };

    public static List<string> EcdsaTokenSigningAlgorithms { get; } = new List<string>
    {
        "ES256",
        "ES384"
    };
}