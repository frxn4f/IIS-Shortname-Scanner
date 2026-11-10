# IIS Short Name Scanner (monolítico)

Un solo archivo: **`iis_shortname_scanner.py`**. Lógica de barrido tomada del PoC de [lijiejie/IIS_shortname_Scanner](https://github.com/lijiejie/IIS_shortname_Scanner), con correcciones (urlparse normalizado, drenado de cola, informe JSON).

Referencia adicional: [irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner) · [bitquark/shortscan](https://github.com/bitquark/shortscan) (Go, wordlist).

**Uso autorizado únicamente.**

## Instalación

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # solo Rich (opcional; sin Rich también funciona)
```

## Uso

```bash
python iis_shortname_scanner.py http://192.168.144.121/
python iis_shortname_scanner.py -v -o report.json http://192.168.144.121/
python iis_shortname_scanner.py --method OPTIONS --force http://192.168.144.121/
```

## Lógica verificada (PoC)

1. **Vulnerabilidad:** `404` en `{base}/*~1*/a.aspx` y **≠404** en `{base}/l1j1e*~1*/a.aspx` (GET y OPTIONS).
2. **Barrido:** petición `{prefix}*~1{ext}/1.aspx`; `404` = coincidencia parcial.
3. **6 caracteres:** `if ext == '.*'` encola directorio **y** el `else` enumera extensiones (no usar `elif` encadenado).
4. **Extensiones cortas:** si `len(ext) < 4` (p.ej. `.cs`) también se encola sin comodín final (changelog Oct 2016).

## Opciones

| Flag | Descripción |
|------|-------------|
| `-t` | Hilos (default 20) |
| `--timeout` | Socket timeout (`None` = como el original) |
| `--method auto\|GET\|OPTIONS` | Método de barrido |
| `--idle` | Segundos con cola vacía antes de cerrar |
| `--force` | Escanear si el check falla |
| `-o` | Informe JSON |

## Correcciones respecto al script original

- `urlparse(self.target)` en lugar del argumento crudo.
- Barrido no termina antes de tiempo (`inflight` + `unfinished_tasks` + idle).
- El método HTTP del chequeo se conserva para el barrido.
- Listas de dirs/files con lock; deduplicación.
