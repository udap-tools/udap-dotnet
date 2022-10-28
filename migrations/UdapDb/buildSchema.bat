rmdir /S /Q "UdapServer"
rmdir /S /Q "../../UdapServer/Migrations"

dotnet ef migrations add InitialUdap  -c UdapDbContext -o Udap/Server/Migrations/UdapDb   --namespace=Udap.Server.Migrations.UdapDb

if errorlevel 1 exit /B 1

dotnet ef migrations script -c UdapDbContext -o Udap/Server/Migrations/UdapDb.sql

if errorlevel 1 exit /B 1

xcopy /s/e/i  .\Udap\Server\Migrations  ..\..\Udap.Server\Migrations

