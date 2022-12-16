#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 5016
EXPOSE 7016

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["NuGet.Config", "."]
COPY ["examples/FhirLabsApi/FhirLabsApi/FhirLabsApi.csproj", "examples/FhirLabsApi/"]
COPY ["Udap.Common/Udap.Common.csproj", "Udap.Common/"]
COPY ["Udap.Metadata.Server/Udap.Metadata.Server.csproj", "Udap.Metadata.Server""]
RUN dotnet restore -f  "FhirLabsApi/FhirLabsApi.csproj"
COPY . .
WORKDIR "/src/examples/FhirLabsApi"
RUN dotnet build "FhirLabsApi.csproj" -c Release -f  -o /app/build

FROM build AS publish
RUN dotnet publish "FhirLabsApi.csproj" -c Release -f -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "FhirLabsApi.dll"]