# ==========================================
# STAGE 1: THE HEAVY COMPILATION SANDBOX
# ==========================================
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env
WORKDIR /app

# 1. DevOps Target-Architecture Optimization
ENV GRPC_PROTOC_PLUGIN_PATH=/usr/bin/grpc_csharp_plugin

# 2. Layered Cache Restorations
COPY *.csproj ./
RUN dotnet restore

# 3. Code Generation & Compilation
COPY . ./
RUN dotnet publish -c Release -o out 

# ==========================================
# STAGE 2: THE LEAN HARDENED PRODUCTION RUNTIME
# ==========================================
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime-env
WORKDIR /app

USER root

# 4. Inject physical system unmanaged device packages
RUN apt-get update && apt-get install -y \
    fswebcam \
    libgpiod2 \
    openssl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/pki

# 5. Extract compiled artifacts securely from Stage 1
COPY --from=build-env /app/out .

RUN chown -R app:app /app && chmod -R 755 /app/pki

USER app

# 6. Open your multi-port networking gateways
EXPOSE 5000
EXPOSE 5001
EXPOSE 4840

# 7. Execute the immutable unmanaged process loop
ENTRYPOINT ["dotnet", "PiOPCUABridge.dll"]
