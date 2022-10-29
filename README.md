# udap-dotnet

UDAP reference implementation for .NET.  

In short UDAP is a PKI extension profile to OAuth2.  On or more PKI's would be hosted by a `Community`.  Joining a `Community` results in a public/private key issued to a client.  The client also chooses to explicitly trust one of the issuing certificates in that chain by installing in your client.  In addition all certificate chain validation including certificate revocation to a trusted root are performed.

Note: This is a new project.  It will take me some time to document.  It should be very active in code changes and document additions.  But feel free to try it out and add issues and/or pull requests.

I am using .NET 7 for a couple projects in here.  In a few weeks .NET 7 will be released.

- `Udap.PKI.Generator`, because there are new X509 features.
- `Udap.Idp.Admin`, because of an annoying bug in Blazor Server related to uploading files.

## What does it support

The repository contains components and example uses to support the following items from [Security for Scalable Registration, Authentication, and Authorization](http://hl7.org/fhir/us/udap-security/).  The intent is to also support generic UDAP, but the driving force at this time is support for auto registration to FHIR servers.

| Feature                 | Supported           | Comments                                               |
|-------------------------|---------------------|--------------------------------------------------------|
| [Discovery](http://hl7.org/fhir/us/udap-security/discovery.html) | ✔️ Including [Multi Trust Communities](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities) | Highly functional.  Could use some advanced tests such as certificate revokation. |
| [Registration](http://hl7.org/fhir/us/udap-security/registration.html)| ✔️ Including [Multi Trust Communities](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities)  |  Functional but needs a lot more tests |
| [Consumer-Facing](http://hl7.org/fhir/us/udap-security/consumer.html)| Not Started | |
| [Business-to-Business](http://hl7.org/fhir/us/udap-security/b2b.html)| In progress | |
| [Tiered OAuth for User Authentication](http://hl7.org/fhir/us/udap-security/user.html) | Not Started | |

## Components (Nuget packages)

### Udap.Metadata.Server

Add this package to your FHIR server or any web api server to join a UDAP community.

### Udap.Client

### Udap.Idp.Server
 
## Build and test

### PKI support

Part of this repository is a xUnit test project that will generate a couple PKI hierarchies for testing UDAP.  The test is called `Udap.PKI.Generator`.  I think showing the mechanics of what it takes to build out a PKI for UDAP will aid education and provide the flexibility to test interesting use cases.  Run all the tests in the `Udap.PKI.Generator` project.  I am not sure if this will stay in unit test form or not, but for now this is the technique.  

### Running tests

Run the WebApi.Tests.  This should result in all tests passing.  WebApi.Tests will test the Udap.Metadata.Server package, configured agains the FhirLabsApi and WeatherApi web service projects.  FhirLabsApi is a simple 
