# udap-dotnet

UDAP reference implementation for .NET.  

In short UDAP is a PKI extension profile to OAuth2.  One or more PKIs can be hosted by a `Community`.  Joining a `Community` results in a public/private key issued to a client.  The client also chooses to explicitly trust one of the issuing certificates in that chain by installing in your client.  In addition, all certificate chain validation including certificate revocation to a trusted root are performed.

Note: This is a new project.  It will take me some time to document.  It should be very active in code changes and document additions.  But feel free to try it out and add issues and/or pull requests.

Many example apps are in the examples folder.

- FHIR® is the registered trademark of HL7 and is used with the permission of HL7. Use of the FHIR trademark does not constitute endorsement of the contents of this repository by HL7.
- UDAP® and the UDAP gear logo, ecosystem gears, and green lock designs are trademarks of UDAP.org. UDAP Draft Specifications are referenced and displayed in parts of this source code to document specification implementation.

## What does it support

The repository contains components and example uses to support the following items from [Security for Scalable Registration, Authentication, and Authorization](http://hl7.org/fhir/us/udap-security/).  The intent is to also support generic UDAP, but the driving force currently is supporting auto registration to FHIR® servers.  

| Feature   | Sub Feature             | Supported           | Comments                                               |
|-------------------------|---|---------------------|--------------------------------------------------------|
| Udap.Client ||||
||UDAP Metadata Validation|✔️| Validates JWT and Certificates.  See [Udap.Client](Udap.Client/docs/README.md) for usage. |
||Dynamic Client Registration|In process| Functionally DCR exists but it has not been packaged and documented in Udap.Client package.|
||Access Token |In process| Functionally exists and needs to be packaged and documented in Udap.Client packages |
||[hl7-b2b extension](http://hl7.org/fhir/us/udap-security/b2b.html#b2b-authorization-extension-object)|In process|This is hard coded in the UdapEd tool for illustration and to pass registration against Authorization Servers that require it.  It is a required claim when requesting an access token in the client_credentials grant type flow profiles by UDAP Security under HL7 FHIR.  I don't know if it stays here as a feature yet.  I do want to call it out because it is a very meaningful feature of UDAP in the HL7 FHIR use case. |  
| [Discovery](http://hl7.org/fhir/us/udap-security/discovery.html): UDAP Metadata for Resource Server||||
| | Udap.Metadata.Server | ✔️ Including [Multi Trust Communities](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities) | Certificate storage is a file strategy.  User can implement their own ICertificateStore.  May add a Entity Framework example and/or HSM in the future.  Checkout the [2023 FHIR® DevDays Tutorial](udap-devdays-2023) to see it in action and the [Udap.Metadata.Server docs](./Udap.Metadata.Server/README.md) |
|| Udap.Metadata.Vonk.Server | Trial status. Including [Multi Trust Communities](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities) | This is based on the same components that build ```Udap.Metadata.Server```.  It can be used as a plugin for the Firely server.  It has been tested on the Community edition.  Readme more in the [docs](./Udap.Metadata.Vonk.Server/README.md)|
| [Server Dynamic Registration](http://hl7.org/fhir/us/udap-security/registration.html)|| ✔️ Including [Multi Trust Communities](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities).<br />  Notes:  Since this development, the Identity Server has Implemented Dynamic Registration.  We need to revisit this and try to enable UDAP under the new DCR feature.  |  Highly Functional.  The Deployed example FHIR® Server, "FhirLabsApi" is passing all udap.org Server Tests.  I am going to revisit the Client Secrets persistence layer.  Packages are dependent on Duende's Identity Server Nuget Packages. <ul><li>✔️ Registration with 201 created</li><li>✔️ Registration with 200 updated</li><li>✔️ Cancel registration with 200</li><li>✔️ Cancel registration with 404 not found</li></ul> |
||Inclusion of Certifications and Endorsements|Started|Some example certification integration tests included from the client side |
Authorization and Authentication
| [Consumer-Facing](http://hl7.org/fhir/us/udap-security/consumer.html)|| ✔️ | Functionality same as B2B authorization_code flow.  Client would typically register and or request user/* prefixed scopes  |
| [Business-to-Business](http://hl7.org/fhir/us/udap-security/b2b.html)|| ✔️ | Works with client_credentials and authorization_code flows. |
||JWT Claim Extensions|Started|Some work completed for the B2B Authorization Extension (hl7-b2b) extension within integration tests. }  
| [Tiered OAuth for User Authentication](http://hl7.org/fhir/us/udap-security/user.html) || Mechanically functional.<br />  Works with hl7_identifier. <br /><br />There is a good integration test called [ClientAuthorize_IdPDiscovery_IdPRegistration_IdPAuthAccess_ClientAuthAccess_Test](/_tests/UdapServer.Tests/Conformance/Tiered/TieredOauthTests.cs). This spins up two in memory instances of Identity Server.  One plays the role of Authorization Server and the other plays the role of Identity Provider.  This test harness is important to quickly test Tiered OAuth without a user interface. I call this test out because going forward we will need to spend some more engineering time deciding if the [TieredOAuthAuthenticationHandler](/Udap.Server/Security/Authentication/TieredOAuth/TieredOAuthAuthenticationHandler.cs) is the final design.  This handler implements the ASP.NET [OAuthHandler](https://github.com/dotnet/aspnetcore/blob/main/src/Security/Authentication/OAuth/src/OAuthHandler.cs) and registered as a scheme.  There is another choice.  We could build the handler based on the [OpenIdConnnect](https://github.com/dotnet/aspnetcore/blob/main/src/Security/Authentication/OpenIdConnect/src/OpenIdConnectHandler.cs) base class.  This is more in line with the Tiered OAuth behavior but a different technique.  OpenIdConnect is more of an event based technique.  When I build this first implementation, I was inspired by other implementations such as this great collection from the [aspnet-contrib](https://github.com/aspnet-contrib) organization, called [AspNet.Security.OpenId.Providers](https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers).  There is another repository at this organization, called [AspNet.Security.OpenId.Providers](https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers).  I have not looked too closely at it yet.  One last thing I would like to mention here, the current implementation of adding a trusted IdP to the Authorization Server is static.  The goal is to transition too dynamic.  For example, this code below represents a sample deployed Auth Server capable of auto registering and federating as to these three IdPs. Duende Identity Server supports "Dynamic Providers" in the Enterprise Server.  This licensing is more expensive.  So maybe future development can allow for static or dynamic.  Remember in Tiered OAuth a client should be able to send an idp parameter in an authorization request, thus initiating a dynamic UDAP relationship between authorization server and IdP server.  <br /><br />Disclaimer, I have not examined this whole code base to see whether parts of the components fit in the different [pricing structures](https://duendesoftware.com/products/identityserver#pricing).  The longer I work with this stack of code the more I appreciate the body of work and the enterprise pricing looks very reasonable.  | Beta status

```csharp

builder.Services.AddAuthentication()
           //
           // By convention the scheme name should match the community name in UdapFileCertStoreManifest
           // to allow discovery of the IdPBaseUrl
           //
           .AddTieredOAuth(options =>
           {
               options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
               options.AuthorizationEndpoint = "https://idp1.securedcontrols.net/connect/authorize";
               options.TokenEndpoint = "https://idp1.securedcontrols.net/connect/token";
               options.IdPBaseUrl = "https://idp1.securedcontrols.net";
           })
           .AddTieredOAuth("TieredOAuthProvider2", "UDAP Tiered OAuth (DOTNET-Provider2)", options =>
           {
               options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
               options.AuthorizationEndpoint = "https://idp2.securedcontrols.net/connect/authorize";
               options.TokenEndpoint = "https://idp2.securedcontrols.net/connect/token";
               options.CallbackPath = "/signin-tieredoauthprovider2";
               options.IdPBaseUrl = "https://idp2.securedcontrols.net";
           })
           .AddTieredOAuth("OktaForUDAP", "UDAP Tiered OAuth Okta", options =>
           {
               options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
               options.AuthorizationEndpoint = "https://udap.zimt.work/oauth2/aus5wvee13EWm169M1d7/v1/authorize";
               options.TokenEndpoint = "https://udap.zimt.work/oauth2/aus5wvee13EWm169M1d7/v1/token";
               options.CallbackPath = "/signin-oktaforudap";
               options.IdPBaseUrl = "https://udap.zimt.work/oauth2/aus5wvee13EWm169M1d7";

           });
```



## PKI support
### Generate PKI for integration tests

Part of this repository is a xUnit test project that will generate a couple PKI hierarchies for testing UDAP.  The test is called `Udap.PKI.Generator`.  I think showing the mechanics of what it takes to build out a PKI for UDAP will aid education and provide the flexibility to test interesting use cases.  Run all the tests in the `Udap.PKI.Generator` project.  The results include a folder with root a root certificate authority that issues intermediate certificates, certificate revocation lists, used certificates for community members and certs for web TLS certs.  Each of the example web services located in the [examples](/examples) use MSBuild `Link`s to link to certificates appropriate to its PKI needs.  So, if you would like to change something in the PKI just edit and run the tests.  All examples will automatically pick up the changes.  To enable crl lookup and AIA, Certification Authority Issuer resolution I just mapped crl, cert and anchor as static content via something like IIS on my Windows box.  I may create a dotnet core app to make this easier and it into ci/cd better but this is where I am at so
I am not sure if this will stay in unit test form or not, but for now this is the technique.  

### Certificate Authority tool

A .NET UI and CLI tool to generate certificates for UDAP communities.  A UI version of this tool is partially done in the [Udap.CA](/examples/Udap.CA/) project.  The plan is to deploy this or install it yourself and allow quick generations of certificates and PKI hierarchies that can generate valid and various invalid certificates for testing to aid in experimenting with behaviors such as certificate revocation, expirations and other interesting potential certification use cases.

## Components (Nuget packages)

See the following Udap.Metadata.Server and Udap.Server sections.  The Udap.Metadata.Server is for the resource server such a FHIR® Server.  Udap.Server.Server is for the Identity Server.

## Udap.Metadata.Server

Follow the [Udap.Metadata.Server docs](./Udap.Metadata.Server/docs/README.md) for configuring your resource server.

## Udap.Client

Follow the [Udap.Client docs](./Udap.Client/docs/README.md) for configuring your UDAP client.

## Udap.Server

Follow the [Udap.Server docs](./Udap.Server/docs/README.md) for configuring your UDAP client.

## Build and test

From root.

```csharp
dotnet restore
```

If this is first build or you want to reset you certificates change to /_tests/Udap.PKI.Generator.  This must be done once.  Other projects are dependent on a lab environment with test PKIs.  This is good in that the development experience will always have PKI structures that do not contain expired certificates unless that is an intended artifact of the data set.

```csharp
dotnet test
```

Return to root

```csharp
dotnet build
```

### Running tests

Again it is probably best to avoid running Udap.PKI.Generator unless you need the certificates regenerated.  I may migrate this away from unit test in future.  Or create a src folder to isolate.  
It is also best to avoid Udap.Client.System.Tests as they are for experimenting with live servers.  Eventually the [FhirLabs UdapEd client tool](/examples/clients/UdapEd/Server/) will replace the need for this.

The following tests are normal to run and the build server runs these same tests.  

- [Udap.CA.Tests](./_tests/Udap.CA.Tests/)
- [Udap.Common.Tests](./_tests/Udap.Common.Tests/)
- [Udap.Support.Tests](./_tests/Udap.Support.Tests/)
- [UdapMetadata.Tests](./_tests/UdapMetadata.Tests/), tests two against the two example web services, FhirLabsApi and WeatherApi.
- [UdapServer.Tests](./_tests/UdapServer.Tests/).  There are times when the bin folder should be deleted because the SQLite DB gets out of sync with the PKI artifacts because the Udap.PKI.Generator tests were ran after the SQLite database is created.  

## Other examples

### UDAP Admin UI Tool

This is a MVP version of an Admin UI Tool.  It is only capable of administering the Udap prefixed tables.

See [Udap.Auth.Server.Admin](./examples/Auth.Server.Admin/)

### UDAP CA UI Tool

This is barely implemented.  The spirit of it is to create a easy to use CA for experimenting in a lab environment.  At this point all the tooling for creating interesting PKI test data for success and failure use cases lives in the Udap.PKI.Generator test project.
