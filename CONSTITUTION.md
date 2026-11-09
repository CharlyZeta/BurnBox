# Constitución del proyecto Burnbox

## Principios Arquitectónicos
1. **Aislamiento criptográfico:** Todo el código criptográfico vive en el módulo `crypto`; no hay uso de `javax.crypto` fuera de él.
2. **Acceso a datos explícito:** No hay JPA ni Hibernate; el acceso a datos es SQL explícito mediante Spring Data JDBC o `JdbcClient`.
3. **Control del tiempo:** Nunca `Instant.now()`, `LocalDateTime.now()` ni `Clock.system*()`; todo el tiempo pasa por un bean `Clock` inyectado.
4. **Fronteras modulares:** Los módulos se comunican únicamente a través de eventos de dominio o puertos públicos declarados; `ApplicationModules.verify()` y ArchUnit deben pasar en cada build.
5. **Vistas seguras:** Prohibido `th:utext`; solo se permite `th:text` con escape contextual.
6. **Defensa en profundidad y dependencias:** Cada comportamiento crítico se prueba con el test más chico posible. No se agrega una dependencia externa sin una nota ADR corta.

## Estándares de Seguridad
7. **Higiene de logs y auditoría:** No se registran tokens, contenido en claro, passphrases, ciphertext ni cabeceras sensibles (`Cookie`, `Authorization`). De un token solo se registran los primeros 8 caracteres de su hash SHA-256. Un test canario en CI verifica la ausencia de secretos en logs.
8. **Sin PII ni secretos en auditoría:** `security_event.details` no almacena información de identificación personal (PII) ni secretos.
9. **Indistinguibilidad para anónimos:** Las respuestas a visitantes anónimos ante un recurso inexistente, vencido, consumido o destruido son idénticas en código HTTP, estructura y mensaje genérico.
10. **Identidad estricta:** La identidad de usuario se define exclusivamente por el par `(issuer, sub)`; ninguna decisión de provisión o acceso se toma basándose en el email ni en los claims `acr`/`amr`.
11. **Matriz de seguridad:** Toda ruta web nueva debe figurar y estar verificada en la matriz de seguridad por rol.
12. **Cero credenciales en repositorio:** Ningún secreto, credencial de cliente ni clave KEK real entra al repositorio; el entorno local se configura mediante variables de entorno documentadas en `.env.example`.
