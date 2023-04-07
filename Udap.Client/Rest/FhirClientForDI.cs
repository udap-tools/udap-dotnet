using Hl7.Fhir.Rest;
using Hl7.Fhir.Specification;
using System.Net.Http.Headers;


namespace Udap.Client.Rest;

/// <summary>
/// I am not sure I like the existing FhirClient.
/// TODO: I might work this some more in the future.
/// </summary>
public class FhirClientForDI : BaseFhirClient
{
    public FhirClientForDI(IBaseUrlProvider baseUrlProvider, HttpClient httpClient, FhirClientSettings? settings = null, IStructureDefinitionSummaryProvider? provider = null)
        : base(baseUrlProvider, httpClient, settings, provider)
    {

        var requester = new HttpClientRequester(baseUrlProvider.GetBaseUrl(), Settings, httpClient);
        Requester = requester;

        // Expose default request headers to user.
        RequestHeaders = requester.Client.DefaultRequestHeaders;
    }

    /// <summary>
    /// Default request headers that can be modified to persist default headers to internal client.
    /// </summary>
    public HttpRequestHeaders RequestHeaders { get; protected set; }
}
