using System.Text.Json;
using Google.Apis.Auth.OAuth2;

namespace Udap.Proxy.Server.Services;


public class AccessTokenService : IAccessTokenService
{
    private const string CloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform";

    private readonly IConfiguration _configuration;
    private readonly SemaphoreSlim _credentialLock = new(1, 1);
    private GoogleCredential? _credential;

    public AccessTokenService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public async Task<string?> ResolveAccessTokenAsync(
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var googleCredentials = await GetCredentialAsync(logger, cancellationToken);
            var token = await googleCredentials.UnderlyingCredential.GetAccessTokenForRequestAsync(cancellationToken: cancellationToken);
            // Never log the token itself: it is a live Google Cloud credential.
            logger.LogDebug("Backend token acquired");
            return token;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed access token access");
        }

        return string.Empty;
    }

    /// <summary>
    /// The credential file named by GoogleCredentialsFile (a service account key, or a user's
    /// application_default_credentials.json) when set, for example in this project's user secrets.
    /// Otherwise Google application default credentials, as on Cloud Run.
    /// </summary>
    private async Task<GoogleCredential> GetCredentialAsync(ILogger logger, CancellationToken cancellationToken)
    {
        if (_credential != null)
        {
            return _credential;
        }

        await _credentialLock.WaitAsync(cancellationToken);
        try
        {
            if (_credential != null)
            {
                return _credential;
            }

            var credentialsFile = _configuration["GoogleCredentialsFile"];
            GoogleCredential credential;

            if (string.IsNullOrWhiteSpace(credentialsFile))
            {
                credential = await GoogleCredential.GetApplicationDefaultAsync(cancellationToken);
            }
            else
            {
                credentialsFile = Environment.ExpandEnvironmentVariables(credentialsFile);
                string credentialType;
                await using (var stream = File.OpenRead(credentialsFile))
                using (var json = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken))
                {
                    credentialType = json.RootElement.GetProperty("type").GetString()!;
                }

                credential = await CredentialFactory.FromFileAsync(credentialsFile, credentialType, cancellationToken);
                logger.LogInformation("Using Google credentials from {CredentialsFile} ({CredentialType})", credentialsFile, credentialType);
            }

            _credential = credential.CreateScoped(CloudPlatformScope);
            return _credential;
        }
        finally
        {
            _credentialLock.Release();
        }
    }
}
