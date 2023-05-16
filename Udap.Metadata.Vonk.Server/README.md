# Udap.Metadata.Vonk.Server

TODO:: configure for Controller or Endpoint style

FYI:: If you are here.  I have spiked this and ran a successful experiment as a Firely plugin.

I still need to spend some time and building a packaging strategy.

Manual steps:  

Copy the following file to the plugins\Udap.Metadata.Vonk.Server\1.0.0\Udap.Metadata.Vonk.Server folder:

- Udap.Common.dll
- Udap.Metadata.Server.dll
- Udap.Metadata.Vonk.Server.dll
- Udap.Model.dll
- Udap.Util.dll
- BouncyCastle.Crypto.dll
- Hl7.Fhir.ElementModel.dll
- Hl7.Fhir.R4B.Core.dll
- Hl7.Fhir.R4B.Specification.dll
- Hl7.Fhir.Support.dll
- Hl7.Fhir.Support.Poco.dll
- Hl7.FhirPath.dll

If I upgrade to Hl7.* to version 5.0 then those libs will most likely not be needed.

