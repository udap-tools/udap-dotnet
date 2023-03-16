using System.Text.Json;
using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using Udap.Idp.Admin.ViewModel;

namespace Udap.Idp.Admin.Services
{
    public class ApiService
    {
        public HttpClient HttpClient;
        IMapper _mapper;

        public ApiService(HttpClient client, IMapper mapper)
        {
            HttpClient = client;
            _mapper = mapper;
        }

        public async Task<ICollection<Community>> GetCommunities()
        {
            var response = await HttpClient.GetFromJsonAsync<ICollection<Common.Models.Community>>("api/community");

            var communities = _mapper.Map<ICollection<Community>>(response);

            return communities;
        }

        public async Task<ICollection<IntermediateCertificate>?> GetRootCertificates()
        {
            var response = await HttpClient.GetFromJsonAsync<ICollection<Common.Models.IntermediateCertificate>>("api/rootCertificate");

            var intermediateCertificates = _mapper.Map<ICollection<IntermediateCertificate>>(response);

            return intermediateCertificates;
        }

        internal async Task<Anchor> Save(Anchor anchorView)
        {
            var anchor = _mapper.Map<Common.Models.Anchor>(anchorView);
            

            var response = await HttpClient.PostAsJsonAsync("api/anchor", anchor).ConfigureAwait(false);
            
            if (response.IsSuccessStatusCode)
            {
                var anchorModel = await response.Content.ReadFromJsonAsync<Common.Models.Anchor>();
                return _mapper.Map<Anchor>(anchorModel);
            }
            else
            {
                var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>().ConfigureAwait(false);
                
                throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions{WriteIndented = true}));
            }
        }

        public async Task Update(Anchor anchorView)
        {
            var anchor = _mapper.Map<Common.Models.Anchor>(anchorView);

            var response = await HttpClient.PutAsJsonAsync($"api/intermediates/{anchor.Id}", anchor).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                return;
            }
            else
            {
                var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>().ConfigureAwait(false);

                throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions { WriteIndented = true }));
            }
        }

        public async Task<bool> DeleteAnchor(long anchorId, CancellationToken token = default)
        {
            var response = await HttpClient.DeleteAsync($"/api/intermediates/{anchorId}");
            
            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>(new JsonSerializerOptions { WriteIndented = true }, token);

            throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions { WriteIndented = true }));
        }


        internal async Task<IntermediateCertificate> Save(IntermediateCertificate intermediateCertificateView)
        {
            var anchor = _mapper.Map<Common.Models.IntermediateCertificate>(intermediateCertificateView);

            var response = await HttpClient.PostAsJsonAsync("api/rootCertificate", anchor).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                var anchorModel = await response.Content.ReadFromJsonAsync<Common.Models.IntermediateCertificate>();
                return _mapper.Map<IntermediateCertificate>(anchorModel);
            }
            else
            {
                var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>().ConfigureAwait(false);

                throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions { WriteIndented = true }));
            }
        }

        public async Task Update(IntermediateCertificate intermediateCertificateView)
        {
            var anchor = _mapper.Map<Common.Models.IntermediateCertificate>(intermediateCertificateView);

            var response = await HttpClient.PutAsJsonAsync($"api/rootCertificate/{anchor.Id}", anchor).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                return;
            }
            else
            {
                var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>().ConfigureAwait(false);

                throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions { WriteIndented = true }));
            }
        }

        public async Task<bool> DeleteIntermediateCertificate(long rootCertificateId, CancellationToken token = default)
        {
            var response = await HttpClient.DeleteAsync($"/api/rootCertificate/{rootCertificateId}");

            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            // var joe = await response.Content.ReadAsStringAsync();
            var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>(new JsonSerializerOptions { WriteIndented = true }, token);

            throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions { WriteIndented = true }));
        }
        
    }
}
