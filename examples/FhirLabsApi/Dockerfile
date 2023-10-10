#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 443 
COPY SureFhirLabs_CA.cer /etc/ssl/certs
RUN update-ca-certificates

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src

COPY ["nuget.config", "."]
COPY ["FhirLabsApi.csproj", "."]
RUN dotnet restore "FhirLabsApi.csproj"
COPY . . 

# Tell the builds to get dependencies from NuGet. 
ENV GCPDeploy=true 
RUN dotnet build "FhirLabsApi.csproj" -c Release -o /app/build 

FROM build AS publish
RUN dotnet publish "FhirLabsApi.csproj" -c Release -o /app/publish /p:UseAppHost=false


FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "FhirLabsApi.dll"]