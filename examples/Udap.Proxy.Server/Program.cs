using IdentityModel;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Udap.Proxy.Server;
using Yarp.ReverseProxy.Transforms;
using Google.Apis.Auth.OAuth2;

var builder = WebApplication.CreateBuilder(args);

// Mount Cloud Secrets
builder.Configuration.AddJsonFile("/secret/udapproxyserverappsettings", true, false);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddUdapMetadataServer(builder.Configuration);

builder.Services.AddAuthentication(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)

    .AddJwtBearer(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer, options =>
    {
        options.Authority = builder.Configuration["Jwt:Authority"];
        options.RequireHttpsMetadata = bool.Parse(builder.Configuration["Jwt:RequireHttpsMetadata"] ?? "true");
        
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("udapPolicy", policy =>
        policy.RequireAuthenticatedUser());
});


builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .ConfigureHttpClient((context, handler) =>
    {
        // this is required to decompress automatically.  *******   troubleshooting only   *******
        handler.AutomaticDecompression = System.Net.DecompressionMethods.All; 
    })
    .AddTransforms(builderContext =>
    {
        // Conditionally add a transform for routes that require auth.
        if (builderContext.Route.Metadata != null && 
            (builderContext.Route.Metadata.ContainsKey("GCPKeyResolve") || builderContext.Route.Metadata.ContainsKey("AccessToken")))
        {
            builderContext.AddRequestTransform(async context =>
            {
                context.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await ResolveAccessToken(builderContext.Route.Metadata));
                // context.ProxyRequest.Headers.Add("X-Authorization-Scope", "user/Patient.read launch/patient");
                // context.ProxyRequest.Headers.Add("X-Authorization-Issuer", "securedcontrols.net");       
            });
        }

        // Use the default credentials.  Primary usage: running in Cloud Run under a specific service account
        if (builderContext.Route.Metadata != null && (builderContext.Route.Metadata.TryGetValue("ADC", out string? adc)))
        {
            if(adc == "True")
            {
                builderContext.AddRequestTransform(async context =>
                {
                    var googleCredentials = GoogleCredential.GetApplicationDefault();
                    string accessToken = await googleCredentials.UnderlyingCredential.GetAccessTokenForRequestAsync();
                    context.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                });
            }
        }
    });

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseDefaultFiles();
app.UseStaticFiles();


app.UseAuthentication();
app.UseAuthorization();

app.MapReverseProxy();

app.UseUdapMetadataServer();

app.Run();


async Task<string?> ResolveAccessToken(IReadOnlyDictionary<string, string> metadata)
{
    try
    {
        if (metadata.ContainsKey("AccessToken"))
        {
            return builder.Configuration.GetValue<string>(metadata["AccessToken"]);
        }

        var routeAuthorizationPolicy = metadata["GCPKeyResolve"];

        var path = builder.Configuration.GetValue<string>(routeAuthorizationPolicy);

        if (string.IsNullOrWhiteSpace(path))
        {
            throw new InvalidOperationException(
                $"The route metadata '{routeAuthorizationPolicy}' must be set to a valid path.");
        }

        var credentials = new ServiceAccountCredentialCache();
        return await credentials.GetAccessTokenAsync(path, "https://www.googleapis.com/auth/cloud-healthcare");
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex); //todo: Logger
        
        return string.Empty;
    }

}


async Task<string> UdapMedatData(string s)
{
    return s;
}