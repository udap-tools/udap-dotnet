using IdentityModel;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Udap.Proxy.Server;
using Yarp.ReverseProxy.Transforms;
using static Google.Apis.Requests.BatchRequest;
using Microsoft.Extensions.Configuration;

var builder = WebApplication.CreateBuilder(args);

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

            builderContext.AddResponseTransform(async context =>
            {
                if (context.HttpContext.Request.Path.Value != null && context.HttpContext.Request.Path.Value.EndsWith(".well-known/udap"))
                {
                    // so the FHIR server would have been hit and respond with a negative operation outcome
                    // May want to keep routes internal to YARP or create a new app service just for serving metadata.
                    // Would Auth Server have new features to serve up metadata for a proxied fhir server?
                    // Almost seems Auth Server should not know about the proxy service.  So maybe not.

                    context.SuppressResponseBody = true;
                    var json = await UdapMedatData(builderContext.Route.Metadata["UdapMetadata"]);
                    context.HttpContext.Response.Headers.Clear();
                    context.HttpContext.Response.StatusCode = (int)HttpStatusCode.OK;
                    await context.HttpContext.Response.Body.WriteAsync(Encoding.UTF8.GetBytes(json));
                }
                else
                {
                    Console.WriteLine("Hello");
                
                    foreach (var responseHeader in context.HttpContext.Response.Headers)
                    {
                        Console.WriteLine($"{responseHeader.Key}: {responseHeader.Value}");
                    }
                
                    var stream = await context.ProxyResponse!.Content.ReadAsStreamAsync();
                    using var reader = new StreamReader(stream);
                    // TODO: size limits, timeouts
                    var body = await reader.ReadToEndAsync();
                    Console.WriteLine(body);
                    context.SuppressResponseBody = true;
                    await context.HttpContext.Response.Body.WriteAsync(Encoding.UTF8.GetBytes(body));
                }
            });
        }
    });

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();
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