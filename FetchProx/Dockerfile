# Build
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish -c Release -o /app /p:UseAppHost=false

# Run
FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app
# Kestrel listen on 8080
ENV ASPNETCORE_URLS=http://0.0.0.0:8080
EXPOSE 8080
COPY --from=build /app .
# Create non-root user and drop privileges
RUN adduser --disabled-password --gecos '' appuser \
    && chown -R appuser /app
USER appuser
ENTRYPOINT ["dotnet", "FetchProx.dll"]
