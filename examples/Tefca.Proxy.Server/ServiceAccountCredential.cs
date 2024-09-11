using Google.Apis.Auth.OAuth2;
using LazyCache;

namespace Tefca.Proxy.Server;


public class ServiceAccountCredentialCache
{
    private readonly IAppCache _cache;
    
    public ServiceAccountCredentialCache()
    {
        _cache = new CachingService();
    }
    public Task<string> GetAccessTokenAsync(string path, params string[] scopes)
    {
        GoogleCredential CachedCredential() => LoadCredential(path, scopes);

        var googleCredential = _cache.GetOrAdd(path, CachedCredential);

        return googleCredential.UnderlyingCredential.GetAccessTokenForRequestAsync();
    }

    private GoogleCredential LoadCredential(string path, params string[] scopes)
    {
        return GoogleCredential
            .FromStream(File.Open(path, FileMode.Open))
            .CreateScoped(scopes);
    }
}