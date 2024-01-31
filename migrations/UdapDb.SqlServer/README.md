# udap-dotnet

### udap-dotnet migrations.

Run buildSchema.bat to regenerate migrations.  It will place migrations in Udap/Server folder

Note: Identity Server migrations were generated from the Duende source code and placed in the Migrations folder at Identity Server version 6.3.

Install dotnet ef tools

dotnet tool install --global dotnet-ef

### Deploy Migratons (new or migrated)

Deploy the schema by simple running this project.  Notice the launchSettings.json file has special configurations
for many environments.  So from Visual Studio you can choose the appropriate environment to migrate.

### How to update Duende Identity Server Migrations
During the Identity Server upgrade to v7 which by the way, is dotnet 8.0 only, the following command was ran to generate the migrations.

 - #### ConfigurationDbContext

   ```dotnet dotnet-ef migrations add ConfigurationDb__v6Tov7  -c ConfigurationDbContext -o Migrations/ConfigurationDb  --namespace=IdentityServerDb.Migrations.ConfigurationDb -- --provider=SqlServer```
 ```dotnet dotnet-ef migrations script -c ConfigurationDbContext -o Migrations/ConfigurationDb.sql```

 - #### PersistedGrantDbContext

   ```dotnet dotnet-ef migrations add PersistedGrantDb__v6Tov7  -c PersistedGrantDbContext -o Migrations/PersistedGrantDb  --namespace=IdentityServerDb.Migrations.PersistedGrantDb -- --provider=SqlServer```
   ```dotnet dotnet-ef migrations script -c PersistedGrantDbContext -o Migrations/PersistedGrantDb.sql```


Add the --verbose flag if troubleshooting.


