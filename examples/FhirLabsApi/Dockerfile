FROM ubuntu:20.04 AS base


#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

#FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 443 
#COPY SureFhirLabs_CA.cer /etc/ssl/certs
#RUN update-ca-certificates

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build

WORKDIR /src

COPY ["nuget.config", "."]
COPY ["FhirLabsApi.csproj", "."]
RUN dotnet restore "FhirLabsApi.csproj"
COPY . . 

# Build a release
ENV GCPDeploy=true
RUN dotnet build "FhirLabsApi.csproj" -c Release -o /app/build 

FROM build AS publish
RUN dotnet publish "FhirLabsApi.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app

# Install system dependencies
RUN set -e; \
    apt-get update -y && apt-get install -y \
    gnupg2 \
    tini \
    lsb-release; \
    gcsFuseRepo=gcsfuse-`lsb_release -c -s`; \
    echo "deb http://packages.cloud.google.com/apt $gcsFuseRepo main" | \
    tee /etc/apt/sources.list.d/gcsfuse.list; \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | \
    apt-key add -; \
    apt-get update; \
    apt-get install -y gcsfuse && apt-get clean

# Set fallback mount directory
ENV MNT_DIR /mnt/gcs


COPY --from=publish /app/publish .
ENV ASPNETCORE_URLS=http://*:8080

# Copy the statup script
COPY gcsfuse_run.sh ./gcsfuse_run.sh
RUN chmod +x ./gcsfuse_run.sh

# Use tini to manage zombie processes and signal forwarding
# https://github.com/krallin/tini
ENTRYPOINT ["/usr/bin/tini", "--"]
#ENTRYPOINT ["dotnet", "FhirLabsApi.dll"]

# Run the web service on container startup.
CMD ["/gcsfuse_run.sh"]


