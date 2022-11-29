# Udap.Metadata.Server

![UDAP logo](https://avatars.githubusercontent.com/u/77421324?s=48&v=4)

## 📦 This package

This package includes a MVC controller, an extension method to load, and an implementation if `ICertificateStore` as `FileCertificateStore` so you can get a sample up and running quickly.

Program.cs could be as easy as this example.

```csharp

using Udap.Common;
using Udap.Metadata.Server;

var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddControllers()
    .UseUdapMetaDataServer(builder.Configuration);

builder.Services.AddSingleton<ICertificateStore, MyCustomCertificateStore>();

```

For a full example of using the `FileCertificateStore` with real generated certificates from your own developer box, follow the instruction in the home [README](../../README.md).
