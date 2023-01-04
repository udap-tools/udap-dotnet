# Benchmark Testing

Using [SuperBenchmarker](https://github.com/aliostad/SuperBenchmarker) to place a load.  

## Example used to test

sb -u "http://localhost:5000/api/Domains/byAnyNames?name=getest3.lab&status=Enabled"  -t BearerGetTemplate.txt -U -c 16 -N 60 -P 1
sb -u "http://devint-directconfig.surescripts-dev.internal/api/Domains/byAnyNames?name=getest3.lab&status=Enabled"  -t BearerGetTemplate.txt -U -c 16 -N 60 -P 1
sb -u "http://devint-directconfig.surescripts-dev.internal/Direct.Config.Api/api/Certificates/byOwner/getest3.lab?IncludeData=true&IncludePrivateKey=true&Status=Enabled"  -t BearerGetTemplate.txt -U -c 16 -N 60 -P 1

sb -u "http://{{{SERVER}}}/Direct.Config.Api/api/Certificates/byOwner/{{{OWNER_NM}}}?IncludeData=true&IncludePrivateKey=true&Status=Enabled"  -t BearerGetTemplate.txt -f FullDomainAndServerData.csv  -U -c 640 -y 100 -N 360 -P 3

Note: Before each test you will need to updated the Bearer Authtoken in the BeaerGetTemplate.txt.

The above was tested against direct.config.api.  There are various examples above.  The more interesting of the tests above is the last test.  I found that while testing against the Devint servers that hitting on of the two servers would result in about 200 rps (requests per second).  But if I tried to call the FQDN of devint-directconfig.surescripts-dev.internal and set the F5 to be roundrobbin it resulted in about 164 rps and still only routed to one of the servers.  Sticky IP rules must have still been in existence but I didn't know how to remove that.  Either way I was able to build a file with all domains (owners) in a file with the two servers in the same data file called FullDomainAndServerData.csv.  Thiw produces a random request to each server using the -U option.  This is probably more accurate to what it would be like to call from a ServiceDiscovery client.  This resulted in 270 requests per second.  Note for this test the Oracle connection string pooling is set to a max of 10.

![Example Load Test](2021-02-28_9-32-54.png)
