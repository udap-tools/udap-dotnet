using Microsoft.Extensions.FileProviders;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

var provider = new Microsoft.AspNetCore.StaticFiles.FileExtensionContentTypeProvider();
// NOTE: Add new mappings
provider.Mappings[".cer"] = "application/x-x509-ca-cert"; // NOTE: add the extension (with period) and its type

builder.Services.AddDirectoryBrowser();
 
var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseStaticFiles(new StaticFileOptions
{
    ContentTypeProvider = provider
});

app.UseDirectoryBrowser(new DirectoryBrowserOptions
{
    FileProvider = new PhysicalFileProvider(Path.Combine(builder.Environment.WebRootPath))
});

app.Run();
