# Multi-stage Dockerfile for SecureWatch ASP.NET Core 10 Web API
FROM mcr.microsoft.com/dotnet/sdk:10.0-preview-alpine AS build
WORKDIR /app

# Copy project files for layer caching
COPY src/backend/SecureWatch.Domain/SecureWatch.Domain.csproj src/backend/SecureWatch.Domain/
COPY src/backend/SecureWatch.Application/SecureWatch.Application.csproj src/backend/SecureWatch.Application/
COPY src/backend/SecureWatch.Infrastructure/SecureWatch.Infrastructure.csproj src/backend/SecureWatch.Infrastructure/
COPY src/backend/SecureWatch.Api/SecureWatch.Api.csproj src/backend/SecureWatch.Api/

# Restore dependencies
RUN dotnet restore src/backend/SecureWatch.Api/SecureWatch.Api.csproj

# Copy source code and build
COPY src/backend/ src/backend/
WORKDIR /app/src/backend/SecureWatch.Api
RUN dotnet publish -c Release -o /app/publish /p:UseAppHost=false

# Runtime Image
FROM mcr.microsoft.com/dotnet/aspnet:10.0-preview-alpine AS runtime
WORKDIR /app
EXPOSE 5000

ENV ASPNETCORE_URLS=http://+:5000 \
    DOTNET_RUNNING_IN_CONTAINER=true \
    ASPNETCORE_ENVIRONMENT=Production

# Install curl for container health check
RUN apk add --no-cache curl

COPY --from=build /app/publish .

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

ENTRYPOINT ["dotnet", "SecureWatch.Api.dll"]

