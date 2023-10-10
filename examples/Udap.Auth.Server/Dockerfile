#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 443
COPY SureFhirLabs_CA.cer /etc/ssl/certs
#Troubleshoot proxy traffic to Touchstone
COPY ngnix-proxy-TestCA.cer /etc/ssl/certs
RUN update-ca-certificates

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src

COPY ["nuget.config", "."]
COPY ["Udap.Auth.Server.csproj", "."]
RUN dotnet restore "Udap.Auth.Server.csproj"
COPY . . 

ENV GCPDeploy=true
RUN dotnet build "Udap.Auth.Server.csproj" -c Release -o /app/build

FROM build AS publish 
RUN dotnet publish "Udap.Auth.Server.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

ENTRYPOINT ["dotnet", "Udap.Auth.Server.dll"]