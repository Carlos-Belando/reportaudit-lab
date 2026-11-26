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

## Parte I: Configuración de Dependabot (Issue #5)

- **Configuración:** Se activaron *Dependency graph*, *Dependabot alerts* y *Dependabot security updates* en el repositorio y se añadió `.github/dependabot.yml` para monitorizar los ecosistemas `pip` y `github-actions` semanalmente.
- **Resultado:** Dependabot abrió automáticamente 4 Pull Requests de actualización (`#18` `sonarqube-scan-action` 7 -> 8, `#19` `actions/checkout` 6 -> 7, `#20` `PyYAML` 6.0.3 -> 6.0.4 y `#21` `Flask` 3.0.0 -> 3.1.3).
- **Evidencias:** `docs/evidencias/i1-dependabot-settings.png` y `docs/evidencias/i3-dependabot-prs.png`.

## Parte M: Remediación de vulnerabilidades (Issue #6)

- **Secretos hardcodeados y exposición en logs (`app/reporte_auditoria.py`):** Se eliminaron `NOTIFICATION_API_KEY` y `SMTP_PASSWORD` del código fuente sustituyéndolas por variables de entorno (`REPORTAUDIT_NOTIFICATION_API_KEY` y `REPORTAUDIT_SMTP_PASSWORD`) y se eliminó el volcado parcial de la clave en `notificar_cliente`. **Declaración de rotación:** Las credenciales expuestas en commits anteriores (`Rq7Hx2Lm9Xc4Vb8Nz1Kd6Fs3Tg5Wy0Pj2Re4UaBt` y `R3port2024!Audit`) se consideran comprometidas y se declaran revocadas/rotadas.
- **Deserialización YAML (`cargar_configuracion`):** Sustitución de `yaml.load(..., Loader=yaml.Loader)` por `yaml.safe_load`.
- **Inyección SQL (`buscar_reportes_cliente`):** Sustitución de concatenación de cadenas por consulta parametrizada (`SELECT * FROM reportes WHERE cliente = ?`).
- **Inyección de comandos (`convertir_a_pdf`):** Validación estricta por expresión regular (`^[a-zA-Z0-9_-]+\.html$`) lanzando `ValueError` ante caracteres no permitidos y ejecución directa con `subprocess.run(..., shell=False)` sin invocación de shell.
- **Algoritmo criptográfico débil (`hash_password_legacy`):** Migración de MD5 sin sal a `hashlib.pbkdf2_hmac("sha256", ..., 600_000)` con sal aleatoria de 16 bytes.
- **Evidencia de verificación:** `docs/evidencias/m-verificacion-remediacion.txt`.
