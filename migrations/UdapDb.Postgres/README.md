# udap-dotnet migrations for PostgreSQL


Install dotnet ef tools

dotnet tool install --global dotnet-ef

### Deploy Migratons (new or migrated)

Deploy the schema by simple running this project.  Notice the launchSettings.json file has special configurations
for many environments.  So from Visual Studio you can choose the appropriate environment to migrate.

### How to build the the first migration

 - #### ConfigurationDbContext

 ``` dotnet dotnet-ef migrations add ConfigurationDB_Initial  -c NpgsqlConfigurationDbContext -o Migrations/ConfigurationDb   -- --provider=Pgsql ```
 ``` dotnet dotnet-ef migrations script -c NpgsqlConfigurationDbContext -o Migrations/ConfigurationDb.sql ```

 - #### PersistedGrantDbContext

   ``` dotnet dotnet-ef migrations add PersistedGrantDb_Initial  -c NpgsqlPersistedGrantDbContext -o Migrations/PersistedGrantDb   -- --provider=Pgsql ```
   ``` dotnet dotnet-ef migrations script -c NpgsqlPersistedGrantDbContext -o Migrations/PersistedGrantDb.sql ```

- #### UdapDbContext

   ``` dotnet dotnet-ef migrations add UdapDb_Initial  -c UdapDbContext -o Migrations/UdapDb   -- --provider=Pgsql ```
   ``` dotnet dotnet-ef migrations script -c UdapDbContext -o Migrations/UdapDb.sql ```
- 
Add the --verbose flag if troubleshooting.


