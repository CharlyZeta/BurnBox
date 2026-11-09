# Stack Tecnológico y Convenciones de Burnbox

## 1. Plataforma y Lenguaje
* **Lenguaje:** Java 25 (LTS)
  * Características utilizadas: *Scoped Values*, *Virtual Threads*, *Records*, *Sealed Interfaces/Classes*, *Pattern Matching*.
* **Build Tool:** Maven (con wrapper `./mvnw`)
* **Encoding:** UTF-8 en todo el código y templates.
* **Control del Tiempo:** Bean `java.time.Clock` inyectado en todo el dominio; prohibido `Instant.now()`, `LocalDateTime.now()` y `Clock.system*()`.

## 2. Frameworks y Módulos Core
* **Framework Principal:** Spring Boot 3.5.3 (preparado para la generación Spring Boot 4.0 / Spring Framework 7 sobre Java 25).
* **Seguridad:** Spring Security (Spring Boot starter)
  * DSL de lambdas obligatorio.
  * Configuración partida en beans `Customizer<HttpSecurity>`.
  * Login OIDC (Google y Microsoft Entra ID multi-tenant) con PKCE.
  * Passkeys / WebAuthn como segundo factor y step-up.
  * Headers de seguridad endurecidos (CSP estricta con nonce, HSTS, `frame-ancestors 'none'`, COOP/CORP `same-origin`).
* **Modularidad:** Spring Modulith
  * Verificación estricta de límites entre módulos con `ApplicationModules.verify()`.
  * Comunicación inter-módulo exclusiva mediante eventos de dominio (`SecurityEventPublisher`).

## 3. Persistencia y Almacenamiento
* **Motor Relacional:** PostgreSQL (única fuente de estado).
* **Acceso a Datos:** Spring Data JDBC y `JdbcClient`
  * SQL explícito para consumo atómico con bloqueo pesimista (`FOR UPDATE`) y consultas por lotes (`SKIP LOCKED`).
  * **Prohibido:** JPA y Hibernate (regla arquitectónica CONSTITUTION.md verificada por ArchUnit).
* **Migraciones de Esquema:** Flyway en `src/main/resources/db/migration/`.
* **Sesiones:** Spring Session JDBC (revocables, con metadatos en tabla propia y cookies endurecidas).
* **Rate Limiting:** Bucket4j con persistencia JDBC sobre PostgreSQL.
* **Coordinación de Jobs:** ShedLock sobre PostgreSQL para `@Scheduled` sobre virtual threads.

## 4. Criptografía (Aislada en módulo `crypto`)
* **Envelope Encryption:**
  * DEK de 256 bits por secreto.
  * Cifrado con AES-256-GCM (nonce aleatorio de 96 bits, tag de autenticación de 128 bits).
  * AAD obligatorio: `id_secreto || version_clave || version_formato`.
* **Tokens de Link:** 32 bytes aleatorios (`SecureRandom`) codificados en base64url sin padding (43 caracteres). La base guarda únicamente el hash SHA-256.
* **Key Provider:** Interfaz `KeyProvider` para envolver/desenvolver DEKs con KEKs versionadas (MVP con adaptador local `LocalKeyProvider` vía variables de entorno `BURNBOX_KEK_V<n>`).
* **KDF de Passphrase:** Argon2id directo con BouncyCastle (`Argon2BytesGenerator`) con límite de concurrencia.

## 5. Frontend y Renderizado SSR
* **Motor de Vistas:** Thymeleaf con fragmentos reutilizables y layouts modulares.
* **Escape Seguro:** Prohibido `th:utext`; exclusivamente `th:text` con escape contextual.
* **Interactividad Ligera:** htmx (actualizaciones de fragmentos sin SPA ni dependencias Node en runtime).
* **Estilos:** Tailwind CSS compilado mediante CLI standalone durante el build de Maven.
* **Internacionalización:** Español (por defecto) e Inglés mediante `MessageSource`.

## 6. Testing y Calidad (Matriz de Pirámide L0 a L6)
* **L0 (Dominio puro):** JUnit 5, AssertJ (criptografía, máquinas de estado, validación de AAD/tampering, reloj simulado `MutableClock`).
* **L1 (Persistencia):** Testcontainers con PostgreSQL real (locks `FOR UPDATE`, consumo exactamente-una-vez concurrente, restricciones de integridad).
* **L2 (Web Slice):** `@WebMvcTest` con Spring Security Test (matriz de rutas por rol, validación de cabeceras de seguridad, CSRF doble envío, errores uniformes).
* **L3 (Módulos):** `@ApplicationModuleTest` (publicación y consumo desacoplado de eventos entre módulos).
* **L4 (Identidad / OIDC):** `mock-oauth2-server` y `oidcLogin()`.
* **L5 (E2E):** Playwright for Java con Chromium y WebAuthn Virtual Authenticator.
* **L6 (No funcional):** ArchUnit, `ApplicationModules.verify()`, test canario de logs (CI falla si aparece un secreto en logs), escaneos de dependencias y Trivy.

## 7. Entorno de Ejecución Local
* **Contenedores:** Docker Compose (`compose.yaml`)
  * `postgres`: PostgreSQL 17/18 con volumen persistente.
  * `mailpit`: Servidor SMTP de pruebas (puerto 1025) con consola web (puerto 8025).
