#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY ["nuget.config", "."]
COPY ["Udap.Identity.Provider.2.csproj", "."]
RUN dotnet restore "Udap.Identity.Provider.2.csproj"
COPY . . 

ENV GCPDeploy=true
RUN dotnet build "Udap.Identity.Provider.2.csproj" -c Release -o /app/build

FROM build AS publish 
RUN dotnet publish "Udap.Identity.Provider.2.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

ENTRYPOINT ["dotnet", "Udap.Identity.Provider.2.dll"]