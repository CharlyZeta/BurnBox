# OAuth 2.0 & OIDC Setup Guide

BurnBox integrates OpenID Connect (OIDC) authentication with **Google** and **Microsoft Entra ID** (multi-tenant `common` endpoint with dynamic issuer validation).

---

## 1. Local Development without OAuth (Demo / Test Mode)

For local development or testing without configuring third-party providers, BurnBox supports anonymous secret creation and consumption out of the box.

To test authenticated features locally:
```bash
# Run with demo profile enabling local dev defaults
./mvnw spring-boot:run -Dspring-boot.run.profiles=demo
```

---

## 2. Google OIDC Configuration

1. Visit [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
2. Create an **OAuth 2.0 Client ID** with Application Type: **Web application**.
3. Set **Authorized redirect URIs**:
   ```
   http://localhost:8080/login/oauth2/code/google
   ```
4. Export the environment variables:
   ```bash
   export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
   export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENT_SECRET="your-client-secret"
   ```

---

## 3. Microsoft Entra ID (Azure AD) Configuration

BurnBox uses a custom dynamic multi-tenant validator (`MicrosoftIssuerValidator`) validating claims against `https://login.microsoftonline.com/{tid}/v2.0` and ensuring `email_verified == true` to prevent nOAuth account takeover attacks.

1. Visit [Azure Portal - App Registrations](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade).
2. Register an application with supported account types: **Accounts in any organizational directory and personal Microsoft accounts**.
3. Set the **Redirect URI** (Web):
   ```
   http://localhost:8080/login/oauth2/code/microsoft
   ```
4. Export the environment variables:
   ```bash
   export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_MICROSOFT_CLIENT_ID="your-app-client-id"
   export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_MICROSOFT_CLIENT_SECRET="your-app-client-secret"
   ```

---

## 4. Production Security Hardening

- Always enforce `https://` on redirect URIs in production.
- Use distinct OAuth app registrations for staging and production.
- Maintain separate client credentials per environment.
