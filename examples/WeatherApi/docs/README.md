# Udap Example: Simple WeatherApi

![UDAP logo](https://avatars.githubusercontent.com/u/77421324?s=48&v=4)

## Web Api

This is a simple Web Api serving up UDAP Metadata using the UdapController.  
Configure the ```/.well-known/udap``` by adding the ```AddUdapMetaDataServer()``` extension method to the IMvcBuilder 
accessible via the ```AddControllers()``` extension method.

```csharp

builder.Services
    .AddControllers()
    .AddUdapMetaDataServer(builder.Configuration);

```