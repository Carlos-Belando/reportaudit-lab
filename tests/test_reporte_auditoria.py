import sqlite3
import tempfile
import pytest

from app.reporte_auditoria import (
    buscar_reportes_cliente,
    cargar_configuracion,
    convertir_a_pdf,
    hash_password_legacy,
    notificar_cliente,
)
import app.servicio as servicio_mod


def test_cargar_configuracion_segura():
    cfg = cargar_configuracion("app/config.yaml")
    assert "servicio" in cfg
    assert cfg["servicio"]["puerto"] == 8087


def test_buscar_reportes_parametrizado():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        conn = sqlite3.connect(tmp.name)
        conn.execute("CREATE TABLE reportes (id INTEGER, cliente TEXT, monto REAL)")
        conn.execute("INSERT INTO reportes VALUES (1, 'acme_corp', 1500.0)")
        conn.execute("INSERT INTO reportes VALUES (2, \"o'brien_ltd\", 700.0)")
        conn.commit()
        conn.close()

        assert len(buscar_reportes_cliente("acme_corp", ruta_db=tmp.name)) == 1
        assert len(buscar_reportes_cliente("o'brien_ltd", ruta_db=tmp.name)) == 1
        assert len(buscar_reportes_cliente("' OR 1=1 --", ruta_db=tmp.name)) == 0


def test_convertir_a_pdf_validacion():
    assert convertir_a_pdf("reporte_01.html") == "reporte_01.html.pdf"
    with pytest.raises(ValueError):
        convertir_a_pdf("reporte.html;id")
    with pytest.raises(ValueError):
        convertir_a_pdf("../secreto.html")
    with pytest.raises(ValueError):
        convertir_a_pdf("")


def test_hash_password_pbkdf2():
    h1 = hash_password_legacy("ClaveSecreta123")
    h2 = hash_password_legacy("ClaveSecreta123")
    assert ":" in h1
    assert h1 != h2


def test_notificar_cliente_sin_exponer_secreto(capsys):
    assert notificar_cliente("cliente@ejemplo.com", "Listo") is True
    salida = capsys.readouterr().out
    assert "Rq7Hx2" not in salida
    assert "NotifyAPI auth=" in salida


def test_endpoints_flask():
    client = servicio_mod.app.test_client()
    r_index = client.get("/")
    assert r_index.status_code == 200

    r_bad = client.get("/convertir?archivo=malo.html;ls")
    assert r_bad.status_code == 400
