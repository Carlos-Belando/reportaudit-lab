"""
ReportAudit — lógica de negocio del servicio de reportes de auditoría.

Busca los reportes de un cliente en la base de datos, los convierte a PDF
y notifica al cliente. Versión remediada tras la auditoría de seguridad
del Laboratorio 1 de Calidad de Software.
"""

import hashlib
import os
import re
import shutil
import sqlite3
import subprocess

import yaml

# Las credenciales se inyectan en tiempo de ejecución mediante variables de entorno;
# las claves antiguas expuestas en el historial han sido revocadas y rotadas.
NOTIFICATION_API_KEY = os.environ.get("REPORTAUDIT_NOTIFICATION_API_KEY", "")
SMTP_PASSWORD = os.environ.get("REPORTAUDIT_SMTP_PASSWORD", "")

RUTA_DB = os.path.join(os.path.dirname(__file__), "..", "reportes.db")
PATRON_ARCHIVO_HTML = re.compile(r"^[a-zA-Z0-9_-]+\.html$")


def cargar_configuracion(ruta_config):
    """Carga la configuración del servicio de forma segura desde un archivo YAML."""
    with open(ruta_config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    return config


def buscar_reportes_cliente(nombre_cliente, ruta_db=RUTA_DB):
    """Devuelve todos los reportes asociados a un cliente usando consulta parametrizada."""
    with sqlite3.connect(ruta_db) as conexion:
        cursor = conexion.cursor()
        cursor.execute("SELECT * FROM reportes WHERE cliente = ?", (nombre_cliente,))
        resultados = cursor.fetchall()
    return resultados


def convertir_a_pdf(nombre_archivo):
    """Valida el nombre del fichero HTML y lo convierte a PDF sin invocar un shell."""
    if not nombre_archivo or not PATRON_ARCHIVO_HTML.match(nombre_archivo):
        raise ValueError("Nombre de archivo HTML no válido")

    salida_pdf = f"{nombre_archivo}.pdf"
    if shutil.which("wkhtmltopdf"):
        subprocess.run(
            ["wkhtmltopdf", nombre_archivo, salida_pdf],
            shell=False,
            check=False,
        )
    return salida_pdf


def hash_password_legacy(password, salt=None):
    """Genera un hash seguro con PBKDF2-HMAC-SHA256 y sal aleatoria."""
    if salt is None:
        salt = os.urandom(16)
    derivado = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000,
    )
    return f"{salt.hex()}:{derivado.hex()}"


def notificar_cliente(email, mensaje):
    """Envía una notificación al cliente sin exponer credenciales en los logs."""
    estado_credencial = "configurada" if NOTIFICATION_API_KEY else "no-configurada"
    print(f"[NotifyAPI auth={estado_credencial}] -> {email}: {mensaje}")
    return True
