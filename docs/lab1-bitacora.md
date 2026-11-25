# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** Carlos Belando Sánchez
- **Repositorio:** https://github.com/Carlos-Belando/reportaudit-lab
- **Sistema operativo y versión de Python usados:**

> Completa cada sección en el momento en que la guía te lo pide, no al final.
> Una bitácora escrita "de memoria" al terminar no sirve como evidencia.

---

## Parte B — Auditoría manual (antes de usar ninguna herramienta)

| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 | buscar_reportes_cliente | 41 | inyección SQL, la query se arma pegando texto en vez de parametrizar | nombre_cliente | cursor.execute(query) |
| 2 | convertir_a_pdf | 49-50 | inyección de comandos | nombre_archivo  | os.system(comando) |
| 3 | cargar_configuracion | 33 | YAML inseguro, el Loader completo puede ejecutar código arbitrario | config.yaml | yaml.load(..., Loader=yaml.Loader) |
| 4 | hash_password_legacy | 57 | hash débil (MD5, sin salt), fácil de romper | password  | hashlib.md5(password.encode()) |
| 5 | Ninguna | 20-22 | credenciales reales escritas directamente en el código | N/A | N/A |

**Impacto en el negocio:** para cada sospecha, explica en una frase qué
consecuencia tendría para ReportAudit y sus clientes si fuera real (qué datos,
qué sistema o qué credencial quedarían expuestos).

---  SQLi = "un atacante ve o borra reportes de cualquier cliente"; inyección de comandos = "control total del servidor"; YAML inseguro = "ejecución de código si se manipula la configuración"; hash débil = "contraseñas fáciles de descifrar si se filtra la BD"; secretos expuestos = "cualquiera con el repo puede suplantar el servicio de notificaciones".

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (K) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` |  |  |  |  |  |  | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` |  |  |  |  |  |  | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` |  |  |  |  |  |  | n/a |
| H4 Hash MD5 en `hash_password_legacy` |  |  |  |  |  |  | n/a |
| H5 Clave de API escrita en el código |  |  |  |  |  |  |  |
| H6 Contraseña SMTP escrita en el código |  |  |  |  |  |  |  |

**Conclusión de la matriz** (Parte K): ¿alguna herramienta lo detectó todo? ¿Qué
te dice eso sobre depender de una sola herramienta?

---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) |  |
| Componentes Python en el SBOM |  |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen |  |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) |  |

---

## Parte J — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |  |

**Comparación con Dependabot** (Parte H): ¿las alertas coinciden con Grype? Explica
cualquier diferencia.

**Documento VEX:** copia `plantillas/reportaudit.openvex.json` a
`docs/evidencias/`, rellénalo, enlázalo aquí y resume en una frase la
justificación.

---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` |  |  |
| Alertas abiertas de CodeQL (Security → Code scanning) |  |  |
| Vulnerabilidades en SonarQube Cloud (rama main) |  |  |
| Security Hotspots por revisar en SonarQube Cloud |  |  |
| Vulnerabilidades de Grype sobre el SBOM |  |  |
| Alertas abiertas de Dependabot |  |  |

---

## Preguntas de comprobación (Sección 7 de la guía)

1.
2.
3.
4.
5.
6.
7.
8.
9.
10.
11.
12.

## Backlog del laboratorio (Issues)

| Issue | Título | PR o evidencia de cierre |
|---|---|---|
| #2 | Adopt an international pull request template | |
| #3 | Run SAST (SonarQube Cloud and CodeQL) on every pull request | |
| #4 | Block insecure commits with a Semgrep pre-commit hook | |
| #5 | Enable Dependabot alerts and security updates | |
| #6 | Remediate the findings of the security audit | |
| #7 | Upgrade the vulnerable dependencies | |
| #8 | Publish the audit log and the before/after evidence | |
| #9 | Detect ReportAudit credentials in the whole Git history | |
| #10 | Make SCA and secret scanning required checks on main | |
| #11 | Publish a security policy and a private vulnerability reporting channel | |
| #12 | Release v1.0.0 with an SBOM and signed provenance | |
| #13 | Measure supply-chain maturity with OpenSSF Scorecard | |

## Parte H: Bloqueo preventivo con Semgrep en pre-commit (Issue #4)

- **Configuración:** `.pre-commit-config.yaml` con `pre-commit-hooks` (`v5.0.0`) y un hook local `semgrep-security` (`semgrep scan --config p/python --config p/secrets --error`).
- **Prueba de bloqueo:** Se intentó commitear un fichero temporal (`app/prueba_insegura.py`) con `subprocess.call(cmd, shell=True)`. El hook bloqueó el commit (`exit code: 1`) mediante la regla `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true`.
- **Evidencia:** `docs/evidencias/semgrep-precommit-bloqueo.txt`.
