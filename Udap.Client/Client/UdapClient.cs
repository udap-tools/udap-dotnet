#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Http.Json;
using Hl7.Fhir.Utility;
using Microsoft.Extensions.Logging;
using Udap.Common.Certificates;
using Udap.Model;

namespace Udap.Client.Client
{

    public interface IUdapClient
    {
        Task<HttpStatusCode> ValidateResource(string baseUrl);
        UdapMetadata? UdapDynamicClientRegistrationDocument { get; set; }
        UdapMetadata? UdapServerMetaData { get; set; }
    }

    public class UdapClient: IUdapClient
    {
        private readonly HttpClient _httpClient;
        private readonly ICertificateStore _certificateStore;
        private readonly ILogger<UdapClient> _logger;

        public UdapClient(HttpClient httpClient, ICertificateStore certificateStore, ILogger<UdapClient> logger)
        {
            _httpClient = httpClient;
            this._certificateStore = certificateStore;
            _logger = logger;
        }

        public UdapMetadata? UdapDynamicClientRegistrationDocument { get; set; }
        public UdapMetadata? UdapServerMetaData { get; set; }

        public async Task<HttpStatusCode> ValidateResource(string baseUrl)
        {
            _httpClient.BaseAddress = new Uri(baseUrl.EnsureEndsWith("/"));

            try
            {
                var response = await _httpClient.GetAsync(".well-known/udap");
                
                if (response.IsSuccessStatusCode)
                {
                    UdapServerMetaData = await response.Content.ReadFromJsonAsync<UdapMetadata>();

                    // var validationResult = ValidateMetadata(UdapServerMetaData);
                }

                return response.StatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed requesting resource metadata");
                return HttpStatusCode.PreconditionFailed;
            }
        }

        private object ValidateMetadata(UdapMetadata udapServerMetaData)
        {
            throw new NotImplementedException();
        }

        
    }
}
