from __future__ import annotations

"""Core scanning engine for knockpy.

This module contains the runtime used by both CLI and Python API:
- domain expansion (`Recon`, `Bruteforce`)
- asynchronous DNS/HTTP/HTTPS checks (`AsyncScanner`)
- orchestration helpers (`_run_async`, `KNOCKPY`)

Keep logic in this file side-effect free where possible, because it is imported
from both `knockpy/cli.py` and external user scripts.
"""

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import socket
import ssl
import string
import sys
import threading
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

import dns.exception
import dns.query
import dns.resolver
import dns.zone
import httpx
import OpenSSL
from dotenv import load_dotenv

from ..server_versions import assess_server_banner, load_server_versions_catalog

load_dotenv()

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = Path.home() / ".knockpy"
RECON_SERVICES_PATH = CONFIG_DIR / "recon_services.json"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

logger = logging.getLogger("knockpy")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))
    logger.addHandler(handler)


def pick_user_agent(useragent: Optional[str]) -> str:
    if useragent and useragent.strip().lower() != "random":
        return useragent.strip()
    return random.choice(USER_AGENTS)


def _www_fallback_domain(domain: str) -> Optional[str]:
    normalized = AsyncScanner._normalize_domain(domain)
    if not normalized:
        return None
    if normalized.startswith("www."):
        return None
    return f"www.{normalized}"


def fmt_td(td: Optional[timedelta]) -> str:
    if td is None:
        return "-"
    total_seconds = int(td.total_seconds())
    hours, rem = divmod(total_seconds, 3600)
    minutes, seconds = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


async def _axfr_check_root(domain: str, dns_server: Optional[str], timeout: float) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()

    def sync_axfr() -> Dict[str, Any]:
        resolver = dns.resolver.Resolver()
        if dns_server:
            resolver.nameservers = [dns_server]
        resolver.timeout = timeout
        resolver.lifetime = max(timeout * 2, timeout + 1.0)

        report: Dict[str, Any] = {"domain": domain, "status": "not-tested", "checks": []}
        try:
            ns_answers = resolver.resolve(domain, "NS")
            ns_list = sorted({str(rr).strip().rstrip(".") for rr in ns_answers if str(rr).strip()})
        except Exception as exc:
            report["status"] = "no-ns"
            report["error"] = f"{exc.__class__.__name__}: {exc}"
            return report

        if not ns_list:
            report["status"] = "no-ns"
            report["error"] = "No NS records found"
            return report

        checks: List[Dict[str, Any]] = []
        for ns in ns_list[:3]:
            entry: Dict[str, Any] = {"ns": ns, "status": "failed", "record_count": None, "error": None}
            try:
                xfr = dns.query.xfr(where=ns, zone=domain, timeout=timeout, lifetime=max(timeout * 2, timeout + 1.0))
                zone = dns.zone.from_xfr(xfr, relativize=False)
                if zone and zone.nodes:
                    entry["status"] = "allowed"
                    entry["record_count"] = len(zone.nodes)
                    checks.append(entry)
                    report["checks"] = checks
                    report["status"] = "allowed"
                    report["allowed_ns"] = ns
                    report["record_count"] = entry["record_count"]
                    return report
                entry["status"] = "denied"
                entry["error"] = "Empty AXFR response"
            except dns.exception.Timeout:
                entry["status"] = "timeout"
                entry["error"] = "Timeout"
            except Exception as exc:
                msg = str(exc)
                low = msg.lower()
                if "refused" in low:
                    entry["status"] = "refused"
                elif "transfer failed" in low or "not authoritative" in low:
                    entry["status"] = "denied"
                else:
                    entry["status"] = "failed"
                entry["error"] = f"{exc.__class__.__name__}: {exc}"
            checks.append(entry)

        report["checks"] = checks
        statuses = {str(c.get("status")) for c in checks}
        if "refused" in statuses:
            report["status"] = "refused"
        elif "denied" in statuses:
            report["status"] = "denied"
        elif "timeout" in statuses and len(statuses) == 1:
            report["status"] = "timeout"
        elif "failed" in statuses and len(statuses) == 1:
            report["status"] = "failed"
        else:
            report["status"] = "closed"
        return report

    return await loop.run_in_executor(None, sync_axfr)


class Bruteforce:
    _WORDLIST_CACHE: Dict[str, Tuple[float, List[str]]] = {}

    def __init__(self, domain: str, wordlist: Optional[str] = None):
        self.domain = domain
        self.wordlist = Path(wordlist) if wordlist else ROOT / "wordlist" / "wordlist.txt"

    def load(self) -> List[str]:
        try:
            wordlist_str = str(self.wordlist)
            mtime = self.wordlist.stat().st_mtime
            cached = self._WORDLIST_CACHE.get(wordlist_str)
            if cached and cached[0] == mtime:
                return cached[1]

            words: List[str] = []
            seen: set[str] = set()
            with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as fh:
                for raw in fh:
                    word = raw.strip().lower()
                    if not word or word.startswith("#"):
                        continue
                    if word in seen:
                        continue
                    seen.add(word)
                    words.append(word)

            self._WORDLIST_CACHE[wordlist_str] = (mtime, words)
            return words
        except FileNotFoundError:
            logger.error("Wordlist not found: %s", self.wordlist)
            return []

    def wildcard(self) -> str:
        rnd = "".join(random.choice(string.ascii_lowercase) for _ in range(random.randint(10, 15)))
        return f"{rnd}.{self.domain}"

    def start(self) -> List[str]:
        words = self.load()
        suffix = f".{self.domain}"
        return [f"{w}{suffix}" for w in words if w]


class Recon:
    """Collect subdomains from configurable external reconnaissance services.

    Used only when `--recon` is enabled (or `recon=True` via Python API).
    Services are read from `~/.knockpy/recon_services.json` and validated to
    avoid leaking API keys to untrusted endpoints.
    """
    HOST_RE = re.compile(r"^[A-Za-z0-9._-]+$")
    RAPIDDNS_RE = re.compile(r"<td>([^<]+)</td>", re.IGNORECASE)
    REMOVED_SERVICES = {"alienvault", "certspotter", "crtsh", "webarchive", "bufferover", "anubis"}
    TRUSTED_API_HOSTS = {
        "virustotal": ("virustotal.com",),
        "shodan": ("shodan.io",),
    }

    def __init__(
        self,
        domain: str,
        timeout: float = 3.0,
        max_concurrency: int = 10,
        useragent: Optional[str] = None,
        virustotal_key: Optional[str] = None,
        shodan_key: Optional[str] = None,
    ):
        self.domain = domain
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.headers = {"User-Agent": pick_user_agent(useragent)}
        self.vt_key = virustotal_key if virustotal_key is not None else os.getenv("API_KEY_VIRUSTOTAL")
        self.shodan_key = shodan_key if shodan_key is not None else os.getenv("API_KEY_SHODAN")

    @staticmethod
    def _default_services() -> List[Dict[str, Any]]:
        return [
            {
                "name": "hackertarget",
                "enabled": True,
                "parser": "csv_first_column",
                "url_template": "https://api.hackertarget.com/hostsearch/?q={domain}",
            },
            {
                "name": "rapiddns",
                "enabled": True,
                "parser": "rapiddns_html_td",
                "url_template": "https://rapiddns.io/subdomain/{domain}",
            },
            {
                "name": "subdomaincenter",
                "enabled": True,
                "parser": "json_list",
                "url_template": "https://api.subdomain.center/?domain={domain}",
            },
            {
                "name": "virustotal",
                "enabled": True,
                "requires_api": "virustotal",
                "parser": "virustotal_subdomains",
                "url_template": "https://www.virustotal.com/vtapi/v2/domain/report?apikey={virustotal_key}&domain={domain}",
            },
            {
                "name": "shodan",
                "enabled": True,
                "requires_api": "shodan",
                "parser": "shodan_subdomains",
                "url_template": "https://api.shodan.io/dns/domain/{domain}?key={shodan_key}",
            },
        ]

    def _recon_config_path(self) -> Path:
        custom = (os.getenv("KNOCK_RECON_SERVICES") or "").strip()
        return Path(custom).expanduser() if custom else RECON_SERVICES_PATH

    def _ensure_recon_config(self) -> Path:
        path = self._recon_config_path()
        if path.is_file():
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
            return path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"version": 1, "services": self._default_services()}
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
        except Exception as exc:
            logger.debug("Cannot create recon services config %s: %s", path, exc)
        return path

    def _load_service_specs(self) -> List[Dict[str, Any]]:
        """Load, sanitize and auto-migrate recon service definitions.

        Why this exists:
        - users can customize service list over time
        - defaults evolve across releases
        - removed/broken services must be filtered out safely
        """
        defaults = self._default_services()
        defaults_by_name = {str(s.get("name") or "").strip().lower(): s for s in defaults}
        path = self._ensure_recon_config()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            services = data.get("services") if isinstance(data, dict) else None
            if isinstance(services, list):
                loaded = [s for s in services if isinstance(s, dict)]
                filtered_loaded: List[Dict[str, Any]] = []
                dropped_removed = False
                for spec in loaded:
                    service_name = str(spec.get("name") or "").strip().lower()
                    if service_name in self.REMOVED_SERVICES:
                        dropped_removed = True
                        continue
                    filtered_loaded.append(spec)
                loaded = filtered_loaded
                loaded_names = {str(s.get("name") or "").strip().lower() for s in loaded}
                missing: List[Dict[str, Any]] = []
                for name, default_spec in defaults_by_name.items():
                    if name and name not in loaded_names:
                        loaded.append(default_spec)
                        missing.append(default_spec)
                if (missing or dropped_removed) and isinstance(data, dict):
                    try:
                        data["services"] = loaded
                        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
                        try:
                            os.chmod(path, 0o600)
                        except Exception:
                            pass
                    except Exception as exc:
                        logger.debug("Cannot update recon services config %s: %s", path, exc)
                return loaded
        except Exception as exc:
            logger.debug("Cannot read recon services config %s: %s", path, exc)
        return defaults

    def _render_service_url(self, template: str) -> Optional[str]:
        """Render and validate a service URL template.

        This function is a security boundary: it blocks malformed or unsafe URLs
        before any network request is sent.
        """
        mapping = {
            "domain": self.domain,
            "virustotal_key": self.vt_key or "",
            "shodan_key": self.shodan_key or "",
        }
        try:
            rendered = template.format(**mapping).strip()
        except Exception:
            return None
        if not rendered.startswith(("http://", "https://")):
            return None
        try:
            parsed = urlparse(rendered)
        except Exception:
            return None
        if parsed.scheme.lower() != "https":
            return None
        if parsed.username or parsed.password:
            return None
        host = (parsed.hostname or "").strip().lower()
        if not host:
            return None
        # Avoid leaking API keys to local/private endpoints from tampered configs.
        if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
            return None
        try:
            ip_obj = ipaddress.ip_address(host)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                return None
        except ValueError:
            pass
        return rendered

    @staticmethod
    def _host_matches_suffix(host: str, suffixes: Tuple[str, ...]) -> bool:
        host_l = (host or "").strip().lower()
        for suffix in suffixes:
            s = suffix.strip().lower()
            if not s:
                continue
            if host_l == s or host_l.endswith("." + s):
                return True
        return False

    def _redact_url_secrets(self, url: Optional[str]) -> Optional[str]:
        if not url:
            return url
        try:
            parts = urlparse(url)
            query = parse_qsl(parts.query, keep_blank_values=True)
            redacted: List[Tuple[str, str]] = []
            for k, v in query:
                key = k.lower()
                if key in {"apikey", "api_key", "key", "token", "access_token"}:
                    redacted.append((k, "***"))
                else:
                    redacted.append((k, v))
            new_query = urlencode(redacted, doseq=True)
            return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, new_query, parts.fragment))
        except Exception:
            return url

    def _redact_text_secrets(self, text: Optional[str]) -> Optional[str]:
        if not text:
            return text
        sanitized = text
        for secret in (self.vt_key, self.shodan_key):
            if secret:
                sanitized = sanitized.replace(secret, "***")
        return sanitized

    def services(self) -> List[Dict[str, str]]:
        """Return executable recon services after policy checks.

        Where used:
        - called by `start()` to build request task list
        Why:
        - centralizes `enabled` filtering, API-key requirements and host policy.
        """
        services: List[Dict[str, str]] = []
        for spec in self._load_service_specs():
            name = str(spec.get("name") or "").strip().lower()
            parser = str(spec.get("parser") or "").strip().lower()
            url_template = str(spec.get("url_template") or "").strip()
            enabled = bool(spec.get("enabled", True))
            requires_api = str(spec.get("requires_api") or "").strip().lower()
            if not enabled or not name or not parser or not url_template or name in self.REMOVED_SERVICES:
                continue
            if requires_api == "virustotal" and not self.vt_key:
                continue
            if requires_api == "shodan" and not self.shodan_key:
                continue
            url = self._render_service_url(url_template)
            if not url:
                continue
            if requires_api in self.TRUSTED_API_HOSTS:
                parsed = urlparse(url)
                host = parsed.hostname or ""
                if not self._host_matches_suffix(host, self.TRUSTED_API_HOSTS[requires_api]):
                    logger.debug("Skipping %s: API key target host not trusted (%s)", name, host)
                    continue
            services.append({"name": name, "parser": parser, "url": url})
        return services

    async def _fetch(self, client: httpx.AsyncClient, name: str, url: str) -> Tuple[str, str]:
        fetch = await self._fetch_with_meta(client, url)
        return name, str(fetch.get("text") or "")

    async def _fetch_with_meta(self, client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
        try:
            response = await client.get(url, timeout=self.timeout, follow_redirects=True)
            response.raise_for_status()
            return {
                "ok": True,
                "status_code": response.status_code,
                "text": response.text,
                "bytes": len(response.content or b""),
                "final_url": str(response.url),
                "error": None,
            }
        except Exception as exc:  # pragma: no cover - network errors are expected
            return {
                "ok": False,
                "status_code": None,
                "text": "",
                "bytes": 0,
                "final_url": None,
                "error": f"{exc.__class__.__name__}: {exc}",
            }

    def _normalize_candidate(self, host: str) -> Optional[str]:
        candidate = (host or "").strip().lower().rstrip(".")
        if not candidate:
            return None
        if candidate.startswith("*."):
            candidate = candidate[2:]
        if not candidate.endswith(self.domain):
            return None
        if not self.HOST_RE.match(candidate):
            return None
        return candidate

    def _parse(self, parser: str, text: str) -> List[str]:
        out: List[str] = []
        if not text:
            return out
        try:
            if parser == "virustotal_subdomains":
                data = json.loads(text)
                out = [s for s in data.get("subdomains", []) if s]
            elif parser == "shodan_subdomains":
                data = json.loads(text)
                out = [f"{s}.{self.domain}" for s in data.get("subdomains", [])]
            elif parser == "csv_first_column":
                out = [line.split(",")[0].strip() for line in text.splitlines() if line.strip() and "," in line]
            elif parser == "rapiddns_html_td":
                out = [m.group(1).strip() for m in self.RAPIDDNS_RE.finditer(text)]
            elif parser in ("json_list", "anubis_list"):
                data = json.loads(text)
                if isinstance(data, list):
                    out = [str(s).strip() for s in data if str(s).strip()]
        except Exception as exc:  # pragma: no cover - parser failures are input-dependent
            logger.debug("Recon parse error %s: %s", parser, exc)

        normalized: List[str] = []
        seen: set[str] = set()
        for candidate in out:
            host = self._normalize_candidate(candidate)
            if host and host not in seen:
                seen.add(host)
                normalized.append(host)
        return normalized

    async def start(self) -> List[str]:
        services = self.services()
        limiter = asyncio.Semaphore(self.max_concurrency)
        timeout_cfg = httpx.Timeout(self.timeout)
        limits_cfg = httpx.Limits(
            max_connections=max(20, self.max_concurrency * 2),
            max_keepalive_connections=max(10, self.max_concurrency),
        )
        results: List[str] = []
        seen: set[str] = set()

        async with httpx.AsyncClient(headers=self.headers, http2=True, timeout=timeout_cfg, limits=limits_cfg) as client:
            tasks = []
            for service in services:
                name = service.get("name", "-")
                parser = service.get("parser", "")
                url = service.get("url", "")
                if not parser or not url:
                    continue

                async def worker(service_name: str = name, service_parser: str = parser, service_url: str = url) -> Tuple[str, str, str]:
                    async with limiter:
                        fetch_name, fetch_text = await self._fetch(client, service_name, service_url)
                        return fetch_name, service_parser, fetch_text

                tasks.append(asyncio.create_task(worker()))

            for coro in asyncio.as_completed(tasks):
                _, parser, text = await coro
                for host in self._parse(parser, text):
                    if host not in seen:
                        seen.add(host)
                        results.append(host)

        return sorted(results)

    async def test_services(self) -> List[Dict[str, Any]]:
        services = self.services()
        limiter = asyncio.Semaphore(self.max_concurrency)
        timeout_cfg = httpx.Timeout(self.timeout)
        limits_cfg = httpx.Limits(
            max_connections=max(20, self.max_concurrency * 2),
            max_keepalive_connections=max(10, self.max_concurrency),
        )
        report: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(headers=self.headers, http2=True, timeout=timeout_cfg, limits=limits_cfg) as client:
            tasks = []
            for service in services:
                name = service.get("name", "-")
                parser = service.get("parser", "")
                url = service.get("url", "")
                if not parser or not url:
                    continue

                async def worker(service_name: str = name, service_parser: str = parser, service_url: str = url) -> Dict[str, Any]:
                    async with limiter:
                        fetch = await self._fetch_with_meta(client, service_url)
                    parsed_count = 0
                    if fetch.get("text"):
                        parsed_count = len(self._parse(service_parser, str(fetch.get("text"))))
                    return {
                        "service": service_name,
                        "parser": service_parser,
                        "url": self._redact_url_secrets(service_url),
                        "ok": bool(fetch.get("ok")),
                        "status_code": fetch.get("status_code"),
                        "response_bytes": int(fetch.get("bytes") or 0),
                        "parsed_count": parsed_count,
                        "error": self._redact_text_secrets(fetch.get("error")),
                        "final_url": self._redact_url_secrets(fetch.get("final_url")),
                    }

                tasks.append(asyncio.create_task(worker()))

            for item in await asyncio.gather(*tasks):
                report.append(item)

        return report


class AsyncScanner:
    """Run DNS, HTTP, HTTPS and certificate checks for one hostname.

    It is instantiated by `_run_async` for each target domain and returns a
    single normalized result object consumed by output/storage layers.
    """
    DNS_CACHE: Dict[str, Tuple[float, Optional[List[str]]]] = {}
    DNS_POSITIVE_TTL = 300.0
    DNS_NEGATIVE_TTL = 30.0
    CNAME_CACHE: Dict[str, Tuple[float, Optional[str]]] = {}
    CNAME_POSITIVE_TTL = 300.0
    CNAME_NEGATIVE_TTL = 60.0
    TLS_PROBE_CACHE: Dict[str, Tuple[float, List[str]]] = {}
    TLS_PROBE_TTL = 600.0
    META_TAG_RE = re.compile(r"""<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>""", re.IGNORECASE)
    META_CONTENT_RE = re.compile(r"""content\s*=\s*(["'])(.*?)\1""", re.IGNORECASE)
    META_URL_RE = re.compile(r"""url\s*=\s*['"]?([^'";\s>]+)""", re.IGNORECASE)
    EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    TAKEOVER_PROVIDERS: List[Dict[str, Any]] = [
        {
            "name": "github-pages",
            "cname_suffixes": ("github.io",),
            "fingerprints": (
                "there isn't a github pages site here",
                "for root urls (like http://example.com/) you must provide an index.html file",
            ),
        },
        {
            "name": "heroku",
            "cname_suffixes": ("herokudns.com", "herokuapp.com"),
            "fingerprints": (
                "no such app",
                "there is no app configured at that hostname",
            ),
        },
        {
            "name": "fastly",
            "cname_suffixes": ("fastly.net",),
            "fingerprints": (
                "fastly error: unknown domain",
                "please check that this domain has been added to a service",
            ),
        },
        {
            "name": "azure",
            "cname_suffixes": ("azurewebsites.net",),
            "fingerprints": (
                "404 web site not found",
                "the resource you are looking for has been removed",
            ),
        },
        {
            "name": "s3-website",
            "cname_suffixes": ("amazonaws.com",),
            "fingerprints": (
                "nosuchbucket",
                "the specified bucket does not exist",
            ),
        },
    ]

    def __init__(
        self,
        domain: str,
        client: httpx.AsyncClient,
        dns_server: Optional[str] = None,
        useragent: Optional[str] = None,
        timeout: float = 2.0,
        cert_semaphore: Optional[asyncio.Semaphore] = None,
        root_domain: Optional[str] = None,
        io_executor: Optional[ThreadPoolExecutor] = None,
        verbose: bool = False,
        api_key_virustotal: Optional[str] = None,
        api_key_shodan: Optional[str] = None,
    ):
        self.domain = domain
        self.client = client
        self.dns_server = dns_server or "8.8.8.8"
        self.headers = {"User-Agent": pick_user_agent(useragent)}
        self.timeout = timeout
        self.cert_semaphore = cert_semaphore or asyncio.Semaphore(50)
        self.root_domain = root_domain or domain
        self.io_executor = io_executor
        self.verbose = verbose
        self.vt_key = api_key_virustotal if api_key_virustotal is not None else os.getenv("API_KEY_VIRUSTOTAL")
        self.shodan_key = api_key_shodan if api_key_shodan is not None else os.getenv("API_KEY_SHODAN")

    async def _resolve_async(self, domain: str) -> Optional[List[str]]:
        normalized = self._normalize_domain(domain)
        if not normalized:
            return None

        now = time.monotonic()
        cached = self.DNS_CACHE.get(normalized)
        if cached is not None:
            expiry, cached_ips = cached
            if expiry > now:
                return cached_ips

        loop = asyncio.get_running_loop()

        def sync_resolve() -> Tuple[Optional[List[str]], float]:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            resolver.timeout = self.timeout
            resolver.lifetime = max(self.timeout * 2, self.timeout + 1.0)

            ips: List[str] = []
            min_ttl = self.DNS_POSITIVE_TTL

            for qtype in ("A", "AAAA"):
                try:
                    answers = resolver.resolve(normalized, qtype)
                except dns.resolver.NXDOMAIN:
                    return None, self.DNS_NEGATIVE_TTL
                except dns.resolver.NoAnswer:
                    continue
                except dns.resolver.NoNameservers:
                    continue
                except dns.exception.Timeout:
                    continue
                except dns.resolver.YXDOMAIN:
                    return None, self.DNS_NEGATIVE_TTL
                except Exception:
                    continue

                if answers.rrset is not None and answers.rrset.ttl is not None:
                    min_ttl = min(min_ttl, float(max(answers.rrset.ttl, 1)))

                for rr in answers:
                    ip_text = str(rr).strip()
                    try:
                        ipaddress.ip_address(ip_text)
                    except ValueError:
                        continue
                    if ip_text not in ips:
                        ips.append(ip_text)

            if not ips:
                return None, self.DNS_NEGATIVE_TTL
            return ips, min(min_ttl, self.DNS_POSITIVE_TTL)

        ips, ttl = await loop.run_in_executor(self.io_executor, sync_resolve)
        self.DNS_CACHE[normalized] = (now + ttl, ips)
        return ips

    async def _resolve_cname_async(self, domain: str) -> Optional[str]:
        normalized = self._normalize_domain(domain)
        if not normalized:
            return None

        now = time.monotonic()
        cached = self.CNAME_CACHE.get(normalized)
        if cached is not None:
            expiry, cached_cname = cached
            if expiry > now:
                return cached_cname

        loop = asyncio.get_running_loop()

        def sync_cname() -> Tuple[Optional[str], float]:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            resolver.timeout = self.timeout
            resolver.lifetime = max(self.timeout * 2, self.timeout + 1.0)
            try:
                answers = resolver.resolve(normalized, "CNAME")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.YXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                return None, self.CNAME_NEGATIVE_TTL
            except Exception:
                return None, self.CNAME_NEGATIVE_TTL

            cname_value: Optional[str] = None
            ttl = self.CNAME_POSITIVE_TTL
            if answers.rrset is not None and answers.rrset.ttl is not None:
                ttl = min(ttl, float(max(answers.rrset.ttl, 1)))
            for rr in answers:
                text = str(rr).strip().rstrip(".").lower()
                if text:
                    cname_value = text
                    break
            if not cname_value:
                return None, self.CNAME_NEGATIVE_TTL
            return cname_value, ttl

        cname, ttl = await loop.run_in_executor(self.io_executor, sync_cname)
        self.CNAME_CACHE[normalized] = (now + ttl, cname)
        return cname

    @staticmethod
    def _status_from_http_tuple(http_data: Tuple[Optional[int], Optional[str], Optional[str], Optional[int], Optional[str], Optional[str], Optional[str]]) -> Optional[int]:
        code = http_data[0] if len(http_data) > 0 else None
        return code if isinstance(code, int) else None

    async def _takeover_check(
        self,
        http: Tuple[Optional[int], Optional[str], Optional[str], Optional[int], Optional[str], Optional[str], Optional[str]],
        https: Tuple[Optional[int], Optional[str], Optional[str], Optional[int], Optional[str], Optional[str], Optional[str]],
    ) -> Optional[Dict[str, Any]]:
        cname = await self._resolve_cname_async(self.domain)
        if not cname:
            return None

        provider: Optional[Dict[str, Any]] = None
        for item in self.TAKEOVER_PROVIDERS:
            suffixes = item.get("cname_suffixes") or ()
            if any(cname == s or cname.endswith("." + s) for s in suffixes):
                provider = item
                break
        if not provider:
            return None

        http_status = self._status_from_http_tuple(http)
        https_status = self._status_from_http_tuple(https)
        preview_text = " ".join(
            str(part or "").lower()
            for part in (
                http[5] if len(http) > 5 else "",
                https[5] if len(https) > 5 else "",
                http[6] if len(http) > 6 else "",
                https[6] if len(https) > 6 else "",
            )
        )

        fingerprints = [str(f).strip().lower() for f in provider.get("fingerprints") or [] if str(f).strip()]
        matched = [f for f in fingerprints if f in preview_text]
        likely = len(matched) > 0
        possible = not likely and any(code in {404, 410} for code in (http_status, https_status) if code is not None)

        if likely:
            status = "likely"
        elif possible:
            status = "possible"
        else:
            status = "none"

        return {
            "status": status,
            "provider": str(provider.get("name") or "unknown"),
            "cname": cname,
            "http_status": http_status,
            "https_status": https_status,
            "matched_fingerprints": matched[:2],
        }

    @staticmethod
    def _normalize_domain(domain: str) -> Optional[str]:
        host = (domain or "").strip().lower()
        if not host:
            return None

        host = re.sub(r"^\w+://", "", host)
        host = host.split("/", 1)[0].strip(".")
        if not host or " " in host:
            return None

        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            return None

        if len(host) > 253:
            return None
        labels = host.split(".")
        if any(not lbl or len(lbl) > 63 for lbl in labels):
            return None
        if any(not re.match(r"^[a-z0-9-]+$", lbl) or lbl.startswith("-") or lbl.endswith("-") for lbl in labels):
            return None
        return host

    def _extract_app_redirect(self, headers: httpx.Headers, content: bytes) -> Optional[str]:
        refresh = headers.get("Refresh")
        if refresh:
            # Examples: "0; URL=https://example.com" / "5;url=/path"
            lower = refresh.lower()
            if "url=" in lower:
                raw = refresh.split("=", 1)[1].strip().strip("'\"")
                if raw:
                    return raw
            if refresh.strip():
                return refresh.strip()

        content_type = (headers.get("Content-Type") or "").lower()
        if "html" not in content_type:
            return None
        if not content:
            return None

        probe = content[:16384].decode("utf-8", errors="ignore")
        meta = self.META_TAG_RE.search(probe)
        if meta:
            tag_text = meta.group(0)
            content_match = self.META_CONTENT_RE.search(tag_text)
            if content_match:
                content_value = content_match.group(2).strip()
                url_match = self.META_URL_RE.search(content_value)
                if url_match:
                    target = url_match.group(1).strip().strip("'\"")
                    return target or None
        return None

    def _body_preview(self, content: bytes, limit: int = 300) -> Optional[str]:
        if not content:
            return None
        text = content[:4096].decode("utf-8", errors="ignore")
        text = re.sub(r"\s+", " ", text).strip()
        if not text:
            return None
        return text[:limit]

    async def _http_check(
        self, url: str
    ) -> Tuple[Optional[int], Optional[str], Optional[str], Optional[int], Optional[str], Optional[str], Optional[str]]:
        try:
            response = await self.client.get(
                url,
                timeout=self.timeout,
                follow_redirects=False,
                headers=self.headers,
            )
            app_redirect = None
            if not response.headers.get("Location"):
                app_redirect = self._extract_app_redirect(response.headers, response.content)
            return (
                response.status_code,
                response.headers.get("Location"),
                response.headers.get("Server"),
                len(response.content),
                app_redirect,
                self._body_preview(response.content),
                None,
            )
        except Exception as exc:
            message = str(exc).strip()
            err = f"{exc.__class__.__name__}: {message}" if message else exc.__class__.__name__
            return None, None, None, None, None, None, err

    def _extract_title(self, content: bytes) -> Optional[str]:
        if not content:
            return None
        text = content[:65536].decode("utf-8", errors="ignore")
        match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
        if not match:
            return None
        title = re.sub(r"\s+", " ", match.group(1)).strip()
        return title or None

    def _security_headers(self, headers: httpx.Headers) -> Dict[str, Optional[str]]:
        keys = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        return {k: headers.get(k) for k in keys}

    def _infra_headers(self, headers: httpx.Headers) -> Dict[str, Optional[str]]:
        keys = ["Server", "Via", "X-Cache", "CF-Ray", "X-Served-By", "X-Powered-By"]
        return {k: headers.get(k) for k in keys}

    async def _dns_detail(self) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()

        def sync_dns() -> Dict[str, Any]:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            resolver.timeout = self.timeout
            resolver.lifetime = max(self.timeout * 2, self.timeout + 1.0)
            out: Dict[str, Any] = {"a": [], "aaaa": [], "cname": [], "ttl": {}, "errors": {}}
            for qtype in ("CNAME", "A", "AAAA"):
                try:
                    answers = resolver.resolve(self.domain, qtype)
                    if answers.rrset is not None and answers.rrset.ttl is not None:
                        out["ttl"][qtype] = int(answers.rrset.ttl)
                    values = [str(rr).strip().rstrip(".") for rr in answers if str(rr).strip()]
                    out[qtype.lower()] = values
                except Exception as exc:
                    out["errors"][qtype] = exc.__class__.__name__
            return out

        return await loop.run_in_executor(self.io_executor, sync_dns)

    async def _tcp_ports(self, ports: Iterable[int] = (80, 443)) -> Dict[str, bool]:
        loop = asyncio.get_running_loop()

        def sync_ports() -> Dict[str, bool]:
            out: Dict[str, bool] = {}
            for port in ports:
                ok = False
                try:
                    with socket.create_connection((self.domain, int(port)), timeout=self.timeout):
                        ok = True
                except Exception:
                    ok = False
                out[str(port)] = ok
            return out

        return await loop.run_in_executor(self.io_executor, sync_ports)

    async def _tls_handshake_detail(self, port: int = 443) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()

        def sync_tls() -> Dict[str, Any]:
            detail: Dict[str, Any] = {
                "strict_ok": False,
                "strict_error": None,
                "protocol": None,
                "cipher": None,
                "alpn": None,
                "issuer": None,
                "subject": None,
                "san": [],
                "san_count": 0,
                "self_signed": None,
                "key_type": None,
                "key_bits": None,
                "signature_algorithm": None,
                "port": port,
            }
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.set_alpn_protocols(["h2", "http/1.1"])
                with socket.create_connection((self.domain, int(port)), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.domain) as tls_sock:
                        detail["strict_ok"] = True
                        detail["protocol"] = tls_sock.version()
                        cipher = tls_sock.cipher()
                        detail["cipher"] = cipher[0] if cipher else None
                        detail["alpn"] = tls_sock.selected_alpn_protocol()
                        cert = tls_sock.getpeercert()
                        if cert:
                            detail["issuer"] = cert.get("issuer")
                            detail["subject"] = cert.get("subject")
                            sans = cert.get("subjectAltName", ())
                            detail["san"] = [v for k, v in sans if k == "DNS"]
                            detail["san_count"] = len(detail["san"])
            except Exception as exc:
                detail["strict_error"] = str(exc)

            # Fill metadata best-effort even on strict failure.
            if not detail["subject"] or not detail["issuer"] or not detail["san"]:
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.set_alpn_protocols(["h2", "http/1.1"])
                    with socket.create_connection((self.domain, int(port)), timeout=self.timeout) as sock:
                        with ctx.wrap_socket(sock, server_hostname=self.domain) as tls_sock:
                            if not detail["protocol"]:
                                detail["protocol"] = tls_sock.version()
                            if not detail["cipher"]:
                                cipher = tls_sock.cipher()
                                detail["cipher"] = cipher[0] if cipher else None
                            if not detail["alpn"]:
                                detail["alpn"] = tls_sock.selected_alpn_protocol()
                            der_cert = tls_sock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert)
                    if not detail["subject"]:
                        detail["subject"] = str(x509.get_subject())
                    if not detail["issuer"]:
                        detail["issuer"] = str(x509.get_issuer())
                    if not detail["san"]:
                        san_values: List[str] = []
                        for i in range(x509.get_extension_count()):
                            ext = x509.get_extension(i)
                            if ext.get_short_name().decode("utf-8").lower() == "subjectaltname":
                                txt = str(ext)
                                for part in txt.split(","):
                                    part = part.strip()
                                    if part.startswith("DNS:"):
                                        san_values.append(part.split(":", 1)[1])
                        detail["san"] = san_values
                        detail["san_count"] = len(san_values)
                    try:
                        detail["self_signed"] = str(x509.get_subject()) == str(x509.get_issuer())
                    except Exception:
                        pass
                    try:
                        pkey = x509.get_pubkey()
                        detail["key_bits"] = int(pkey.bits()) if pkey else None
                        key_type_id = pkey.type() if pkey else None
                        key_type_map = {
                            getattr(OpenSSL.crypto, "TYPE_RSA", 6): "RSA",
                            getattr(OpenSSL.crypto, "TYPE_DSA", 116): "DSA",
                            getattr(OpenSSL.crypto, "TYPE_EC", 408): "EC",
                        }
                        detail["key_type"] = key_type_map.get(key_type_id, str(key_type_id) if key_type_id is not None else None)
                    except Exception:
                        pass
                    try:
                        detail["signature_algorithm"] = x509.get_signature_algorithm().decode("utf-8")
                    except Exception:
                        pass
                except Exception:
                    pass

            return detail

        return await loop.run_in_executor(self.io_executor, sync_tls)

    async def _request_detail(self, url: str, follow_redirects: bool = True, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        try:
            started = time.perf_counter()
            response = await self.client.get(
                url,
                timeout=self.timeout,
                follow_redirects=follow_redirects,
                headers=headers or self.headers,
            )
            total_ms = int((time.perf_counter() - started) * 1000)

            chain: List[Dict[str, Any]] = []
            for hop in list(response.history) + [response]:
                loc = hop.headers.get("Location")
                app_loc = None if loc else self._extract_app_redirect(hop.headers, hop.content)
                chain.append(
                    {
                        "url": str(hop.url),
                        "status": hop.status_code,
                        "location": loc,
                        "app_redirect": app_loc,
                        "elapsed_ms": int(hop.elapsed.total_seconds() * 1000) if hop.elapsed else None,
                    }
                )

            body = response.content or b""
            body_sample = body[:131072].decode("utf-8", errors="ignore")
            return {
                "ok": True,
                "url": str(response.url),
                "status": response.status_code,
                "history": chain,
                "content_type": response.headers.get("Content-Type"),
                "title": self._extract_title(body),
                "sha256": hashlib.sha256(body).hexdigest() if body else None,
                "body_bytes": len(body),
                "body_sample": body_sample,
                "total_ms": total_ms,
                "http_version": response.http_version,
                "security_headers": self._security_headers(response.headers),
                "infra_headers": self._infra_headers(response.headers),
                "set_cookie": response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else [],
                "allow": response.headers.get("Allow"),
                "hsts": response.headers.get("Strict-Transport-Security"),
            }
        except Exception as exc:
            message = str(exc).strip()
            err = f"{exc.__class__.__name__}: {message}" if message else exc.__class__.__name__
            return {"ok": False, "error": err}

    async def _security_txt_check(self) -> Dict[str, Any]:
        url = f"https://{self.domain}/.well-known/security.txt"
        try:
            response = await self.client.get(url, timeout=self.timeout, follow_redirects=True, headers=self.headers)
            text = response.text or ""
            has_contact = "contact:" in text.lower()
            has_expires = "expires:" in text.lower()
            return {
                "url": str(response.url),
                "status": response.status_code,
                "has_contact": has_contact,
                "has_expires": has_expires,
                "present": response.status_code == 200 and "contact:" in text.lower(),
            }
        except Exception as exc:
            return {"url": url, "status": None, "present": False, "error": f"{exc.__class__.__name__}: {exc}"}

    async def _caa_check(self) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()

        def sync_caa() -> Dict[str, Any]:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            resolver.timeout = self.timeout
            resolver.lifetime = max(self.timeout * 2, self.timeout + 1.0)
            try:
                answers = resolver.resolve(self.domain, "CAA")
                entries: List[str] = [str(rr).strip() for rr in answers if str(rr).strip()]
                return {"present": bool(entries), "entries": entries}
            except dns.resolver.NoAnswer:
                return {"present": False, "entries": []}
            except dns.resolver.NXDOMAIN:
                return {"present": False, "entries": [], "error": "NXDOMAIN"}
            except Exception as exc:
                return {"present": False, "entries": [], "error": f"{exc.__class__.__name__}: {exc}"}

        return await loop.run_in_executor(self.io_executor, sync_caa)

    @staticmethod
    def _txt_rr_to_text(rr: Any) -> str:
        chunks = getattr(rr, "strings", None)
        if isinstance(chunks, (list, tuple)) and chunks:
            parts: List[str] = []
            for chunk in chunks:
                if isinstance(chunk, (bytes, bytearray)):
                    parts.append(chunk.decode("utf-8", errors="ignore"))
                else:
                    parts.append(str(chunk))
            return "".join(parts).strip()

        text = str(rr).strip()
        if text.startswith('"') and text.endswith('"') and len(text) >= 2:
            text = text[1:-1]
        return text.replace('" "', "").strip()

    @staticmethod
    def _parse_tag_list(record: str) -> Dict[str, str]:
        tags: Dict[str, str] = {}
        for part in (record or "").split(";"):
            token = part.strip()
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            k = key.strip().lower()
            v = value.strip()
            if k:
                tags[k] = v
        return tags

    @staticmethod
    def _estimate_dkim_key_bits(p_value: Optional[str]) -> Optional[int]:
        if not p_value:
            return None
        raw = re.sub(r"\s+", "", str(p_value))
        if not raw:
            return None
        if not re.fullmatch(r"[A-Za-z0-9+/=]+", raw):
            return None
        padding = 0
        if raw.endswith("=="):
            padding = 2
        elif raw.endswith("="):
            padding = 1
        key_bytes = max(0, (len(raw) * 3 // 4) - padding)
        if key_bytes <= 0:
            return None
        return key_bytes * 8

    async def _email_auth_detail(self) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()

        def sync_email_auth() -> Dict[str, Any]:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            resolver.timeout = self.timeout
            resolver.lifetime = max(self.timeout * 2, self.timeout + 1.0)

            root = self.domain.strip().rstrip(".")

            def resolve_txt(name: str) -> Tuple[List[str], Optional[str]]:
                try:
                    answers = resolver.resolve(name, "TXT")
                    values = [self._txt_rr_to_text(rr) for rr in answers]
                    clean = [v for v in values if v]
                    return clean, None
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    return [], None
                except Exception as exc:
                    return [], f"{exc.__class__.__name__}: {exc}"

            root_txt, root_err = resolve_txt(root)
            dmarc_txt, dmarc_err = resolve_txt(f"_dmarc.{root}")

            spf_records = [r for r in root_txt if r.lower().startswith("v=spf1")]
            spf_all = None
            spf_policy = "missing"
            spf_level = "warning"
            spf_summary = "SPF record not found"
            if spf_records:
                rec = spf_records[0]
                all_match = re.search(r"(?:^|\s)([+\-~?])?all(?:\s|$)", rec, flags=re.IGNORECASE)
                qualifier = all_match.group(1) if all_match else None
                spf_all = qualifier if qualifier is not None else ("+" if all_match else None)
                if len(spf_records) > 1:
                    spf_policy = "ambiguous"
                    spf_level = "warning"
                    spf_summary = f"Multiple SPF records found ({len(spf_records)})"
                elif spf_all == "-":
                    spf_policy = "strict"
                    spf_level = "ok"
                    spf_summary = "SPF configured with hard fail (-all)"
                elif spf_all == "~":
                    spf_policy = "soft"
                    spf_level = "info"
                    spf_summary = "SPF configured with soft fail (~all)"
                elif spf_all in {"+", "?"}:
                    spf_policy = "weak"
                    spf_level = "warning"
                    spf_summary = f"SPF policy is weak ({spf_all}all)"
                elif "redirect=" in rec.lower():
                    spf_policy = "redirect"
                    spf_level = "info"
                    spf_summary = "SPF uses redirect= policy"
                else:
                    spf_policy = "incomplete"
                    spf_level = "warning"
                    spf_summary = "SPF present but missing explicit all policy"

            dmarc_records = [r for r in dmarc_txt if r.lower().startswith("v=dmarc1")]
            dmarc_tags: Dict[str, str] = self._parse_tag_list(dmarc_records[0]) if dmarc_records else {}
            dmarc_policy = (dmarc_tags.get("p") or "").strip().lower()
            dmarc_pct = self._as_int(dmarc_tags.get("pct"), default=100)
            dmarc_level = "warning"
            dmarc_summary = "DMARC record not found"
            if dmarc_records:
                if dmarc_policy in {"reject", "quarantine"} and dmarc_pct >= 100:
                    dmarc_level = "ok"
                    dmarc_summary = f"DMARC enforced (p={dmarc_policy}, pct={dmarc_pct})"
                elif dmarc_policy in {"reject", "quarantine"}:
                    dmarc_level = "info"
                    dmarc_summary = f"DMARC partially enforced (p={dmarc_policy}, pct={dmarc_pct})"
                elif dmarc_policy == "none":
                    dmarc_level = "warning"
                    dmarc_summary = "DMARC monitor-only policy (p=none)"
                elif dmarc_policy:
                    dmarc_level = "info"
                    dmarc_summary = f"DMARC policy set to p={dmarc_policy}"
                else:
                    dmarc_level = "warning"
                    dmarc_summary = "DMARC present but missing p= policy"

            selectors = [
                "default",
                "selector1",
                "selector2",
                "google",
                "k1",
                "k2",
                "smtp",
                "mail",
                "mx",
                "dkim",
                "zoho",
                "mandrill",
            ]
            found_dkim: List[Dict[str, Any]] = []
            lookup_errors: List[str] = []
            for selector in selectors:
                qname = f"{selector}._domainkey.{root}"
                records, err = resolve_txt(qname)
                if err:
                    lookup_errors.append(f"{selector}:{err}")
                    continue
                dkim_records = [r for r in records if r.lower().startswith("v=dkim1")]
                if not dkim_records:
                    continue
                for record in dkim_records:
                    tags = self._parse_tag_list(record)
                    bits = self._estimate_dkim_key_bits(tags.get("p"))
                    found_dkim.append(
                        {
                            "selector": selector,
                            "record": record,
                            "tags": tags,
                            "key_bits_est": bits,
                            "revoked": tags.get("p", "").strip() == "",
                        }
                    )

            dkim_level = "info"
            dkim_summary = "No DKIM key found in common selectors (non-exhaustive)"
            if found_dkim:
                revoked = [d for d in found_dkim if d.get("revoked")]
                weak = [d for d in found_dkim if isinstance(d.get("key_bits_est"), int) and int(d["key_bits_est"]) < 2048]
                if revoked:
                    dkim_level = "warning"
                    dkim_summary = f"DKIM selectors found but {len(revoked)} key(s) revoked"
                elif weak:
                    dkim_level = "warning"
                    dkim_summary = f"DKIM key too short on {len(weak)} selector(s) (<2048 bits)"
                else:
                    dkim_level = "ok"
                    dkim_summary = f"DKIM selector(s) found: {', '.join(sorted({d['selector'] for d in found_dkim}))}"

            max_bits = max(
                [int(d.get("key_bits_est")) for d in found_dkim if isinstance(d.get("key_bits_est"), int)],
                default=None,
            )

            return {
                "spf": {
                    "present": bool(spf_records),
                    "records": spf_records[:3],
                    "all_qualifier": spf_all,
                    "policy": spf_policy,
                    "level": spf_level,
                    "summary": spf_summary,
                    "lookup_error": root_err,
                },
                "dmarc": {
                    "present": bool(dmarc_records),
                    "records": dmarc_records[:3],
                    "policy": dmarc_policy or None,
                    "pct": dmarc_pct if dmarc_records else None,
                    "adkim": dmarc_tags.get("adkim"),
                    "aspf": dmarc_tags.get("aspf"),
                    "rua": dmarc_tags.get("rua"),
                    "ruf": dmarc_tags.get("ruf"),
                    "level": dmarc_level,
                    "summary": dmarc_summary,
                    "lookup_error": dmarc_err,
                },
                "dkim": {
                    "present_common_selectors": bool(found_dkim),
                    "selectors_checked": selectors,
                    "selectors_found": sorted({str(d.get("selector")) for d in found_dkim if d.get("selector")}),
                    "records": [str(d.get("record") or "") for d in found_dkim[:8] if str(d.get("record") or "")],
                    "max_key_bits_est": max_bits,
                    "non_exhaustive": True,
                    "level": dkim_level,
                    "summary": dkim_summary,
                    "lookup_errors": lookup_errors[:5],
                },
            }

        return await loop.run_in_executor(self.io_executor, sync_email_auth)

    async def _dns_takeover_hints(self) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()

        def sync_takeover() -> Dict[str, Any]:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            resolver.timeout = self.timeout
            resolver.lifetime = max(self.timeout * 2, self.timeout + 1.0)
            providers = (
                "github.io",
                "herokudns.com",
                "azurewebsites.net",
                "cloudfront.net",
                "fastly.net",
                "pantheonsite.io",
                "readthedocs.io",
                "surge.sh",
            )
            try:
                answers = resolver.resolve(self.domain, "CNAME")
                cnames = [str(rr).strip().rstrip(".").lower() for rr in answers if str(rr).strip()]
            except Exception:
                return {"suspect": False, "cnames": []}

            hints: List[str] = []
            for cname in cnames:
                if not any(suffix in cname for suffix in providers):
                    continue
                try:
                    has_a = bool(resolver.resolve(cname, "A"))
                except Exception:
                    has_a = False
                try:
                    has_aaaa = bool(resolver.resolve(cname, "AAAA"))
                except Exception:
                    has_aaaa = False
                if not has_a and not has_aaaa:
                    hints.append(cname)
            return {"suspect": bool(hints), "cnames": cnames, "suspect_targets": hints}

        return await loop.run_in_executor(self.io_executor, sync_takeover)

    async def _open_redirect_probe(self) -> Dict[str, Any]:
        probes = ["next", "url", "redirect"]
        base = f"https://{self.domain}/"
        out: List[Dict[str, Any]] = []
        for p in probes:
            url = f"{base}?{p}=https://example.com"
            try:
                r = await self.client.get(url, headers=self.headers, timeout=self.timeout, follow_redirects=False)
                loc = r.headers.get("Location")
                maybe_open = False
                if loc:
                    try:
                        parsed = urlparse(loc)
                        host = (parsed.hostname or "").lower()
                        if host and host == "example.com":
                            maybe_open = True
                    except Exception:
                        maybe_open = False
                out.append({"param": p, "status": r.status_code, "location": loc, "possible_open_redirect": maybe_open})
            except Exception as exc:
                out.append({"param": p, "status": None, "location": None, "error": f"{exc.__class__.__name__}: {exc}"})
        return {"possible": any(bool(x.get("possible_open_redirect")) for x in out), "probes": out}

    async def _http_methods_check(self) -> Dict[str, Any]:
        def _split_methods(raw: str) -> List[str]:
            return [m.strip().upper() for m in (raw or "").split(",") if m.strip()]

        def _collect_from_response(response: Any) -> Tuple[set[str], set[str]]:
            allow_set: set[str] = set()
            cors_set: set[str] = set()
            if response is None:
                return allow_set, cors_set

            chain = list(getattr(response, "history", []) or []) + [response]
            for part in chain:
                headers = getattr(part, "headers", None)
                if headers is None:
                    continue
                allow_set.update(_split_methods(headers.get("Allow") or ""))
                cors_set.update(_split_methods(headers.get("Access-Control-Allow-Methods") or ""))
            return allow_set, cors_set

        async def infer_safe_methods(url: str) -> List[str]:
            # Probe a random non-existing path to minimize side effects while
            # checking whether common methods are handled by the target stack.
            token = "".join(random.choice(string.ascii_lowercase) for _ in range(12))
            target = f"{url.rstrip('/')}/.knockpy-method-probe-{token}"
            supported: List[str] = []
            for method in ("GET", "HEAD", "POST", "OPTIONS"):
                try:
                    resp = await self.client.request(
                        method,
                        target,
                        headers=self.headers,
                        timeout=self.timeout,
                        follow_redirects=True,
                        content=b"" if method == "POST" else None,
                    )
                except Exception:
                    continue
                if int(resp.status_code) not in {405, 501}:
                    supported.append(method)
            return supported

        async def check(url: str) -> Dict[str, Any]:
            try:
                r_follow = await self.client.options(url, headers=self.headers, timeout=self.timeout, follow_redirects=True)
                allow_set, cors_set = _collect_from_response(r_follow)

                # Some servers expose method metadata only before redirects or only
                # on non-followed OPTIONS responses.
                r_nofollow = await self.client.options(url, headers=self.headers, timeout=self.timeout, follow_redirects=False)
                allow_nf, cors_nf = _collect_from_response(r_nofollow)
                allow_set.update(allow_nf)
                cors_set.update(cors_nf)
                inferred = await infer_safe_methods(url)

                return {
                    "status": r_follow.status_code,
                    "allow": sorted(allow_set),
                    "cors_allow": sorted(cors_set),
                    "inferred_safe": inferred,
                }
            except Exception as exc:
                return {
                    "status": None,
                    "allow": [],
                    "cors_allow": [],
                    "inferred_safe": [],
                    "error": f"{exc.__class__.__name__}: {exc}",
                }

        http_res, https_res = await asyncio.gather(check(f"http://{self.domain}"), check(f"https://{self.domain}"))
        risky = {"PUT", "DELETE", "TRACE", "CONNECT"}
        observed = (
            set(http_res.get("allow") or [])
            | set(https_res.get("allow") or [])
            | set(http_res.get("cors_allow") or [])
            | set(https_res.get("cors_allow") or [])
        )
        exposed = sorted(observed & risky)
        inferred_union = sorted(
            set(http_res.get("inferred_safe") or []) | set(https_res.get("inferred_safe") or [])
        )
        return {"http": http_res, "https": https_res, "risky_methods": exposed, "inferred_safe": inferred_union}

    async def _rate_limit_waf_check(self) -> Dict[str, Any]:
        statuses: List[Optional[int]] = []
        flags: List[str] = []
        for _ in range(3):
            try:
                r = await self.client.get(f"https://{self.domain}", headers=self.headers, timeout=self.timeout, follow_redirects=True)
                statuses.append(r.status_code)
                body = (r.text or "")[:4000].lower()
                if "captcha" in body or "attention required" in body or "cloudflare" in body and "ray id" in body:
                    flags.append("challenge")
            except Exception:
                statuses.append(None)
        return {"statuses": statuses, "rate_limited": any(s == 429 for s in statuses if s is not None), "waf_flags": sorted(set(flags))}

    def _redact_api_secrets(self, text: Optional[str]) -> Optional[str]:
        if not text:
            return text
        redacted = text
        for secret in (self.vt_key, self.shodan_key):
            if secret:
                redacted = redacted.replace(secret, "***")
        return redacted

    @staticmethod
    def _as_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return default

    @staticmethod
    def _as_float(value: Any) -> Optional[float]:
        try:
            return float(value)
        except Exception:
            return None

    @staticmethod
    def _iso_from_epoch(value: Any) -> Optional[str]:
        try:
            ts = int(value)
            return datetime.fromtimestamp(ts, timezone.utc).replace(tzinfo=None).isoformat() + "Z"
        except Exception:
            return None

    @staticmethod
    def _cvss_severity(score: Optional[float]) -> str:
        if score is None:
            return "unknown"
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "none"

    def _normalize_shodan_vulns(self, vulns_obj: Any) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        if isinstance(vulns_obj, dict):
            for cve_id_raw, meta in vulns_obj.items():
                cve_id = str(cve_id_raw).strip()
                if not cve_id:
                    continue
                score: Optional[float] = None
                if isinstance(meta, dict):
                    for key in ("cvss", "cvss_v3", "cvss3", "cvss_score", "cvss3_score", "score"):
                        if key in meta:
                            score = self._as_float(meta.get(key))
                            if score is not None:
                                break
                entries.append(
                    {
                        "id": cve_id,
                        "score": score,
                        "severity": self._cvss_severity(score),
                    }
                )
        elif isinstance(vulns_obj, list):
            for item in vulns_obj:
                cve_id = str(item).strip()
                if cve_id:
                    entries.append({"id": cve_id, "score": None, "severity": "unknown"})

        return sorted(
            entries,
            key=lambda x: (
                -(x.get("score") if isinstance(x.get("score"), (int, float)) else -1.0),
                str(x.get("id") or ""),
            ),
        )

    @staticmethod
    def _vt_category_bucket(label: str) -> str:
        text = (label or "").strip().lower()
        if not text:
            return "unknown"
        if any(k in text for k in ("phish", "credential", "brand", "fake login")):
            return "phishing"
        if any(k in text for k in ("malware", "trojan", "ransom", "worm", "virus", "botnet", "c2", "backdoor")):
            return "malware"
        if any(k in text for k in ("spam", "scam", "fraud")):
            return "fraud/scam"
        if any(k in text for k in ("suspicious", "unknown")):
            return "suspicious"
        return text

    def _vt_dominant_threat_category(self, attrs: Dict[str, Any]) -> str:
        votes: Dict[str, int] = {}

        categories_map = attrs.get("categories") or {}
        if isinstance(categories_map, dict):
            for raw in categories_map.values():
                bucket = self._vt_category_bucket(str(raw))
                votes[bucket] = votes.get(bucket, 0) + 1

        analysis_results = attrs.get("last_analysis_results") or {}
        if isinstance(analysis_results, dict):
            for engine_data in analysis_results.values():
                if not isinstance(engine_data, dict):
                    continue
                if str(engine_data.get("category") or "").strip().lower() not in {"malicious", "suspicious"}:
                    continue
                label = str(engine_data.get("result") or engine_data.get("category") or "")
                bucket = self._vt_category_bucket(label)
                votes[bucket] = votes.get(bucket, 0) + 1

        if not votes:
            return "unknown"
        return sorted(votes.items(), key=lambda x: (-x[1], x[0]))[0][0]

    def _vt_dns_anomalies(self, attrs: Dict[str, Any]) -> List[str]:
        anomalies: List[str] = []
        records = attrs.get("last_dns_records") or []
        if not isinstance(records, list):
            return anomalies

        provider_suffixes = (
            "github.io",
            "herokudns.com",
            "azurewebsites.net",
            "cloudfront.net",
            "fastly.net",
            "pantheonsite.io",
            "readthedocs.io",
            "surge.sh",
        )
        for rec in records[:80]:
            if not isinstance(rec, dict):
                continue
            rtype = str(rec.get("type") or "").strip().upper()
            value = str(rec.get("value") or rec.get("rdata") or "").strip().lower().rstrip(".")
            if not rtype or not value:
                continue
            if rtype in {"A", "AAAA"}:
                try:
                    ip_obj = ipaddress.ip_address(value)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                        anomalies.append(f"{rtype} points to non-public IP {value}")
                except Exception:
                    continue
            elif rtype == "CNAME":
                if any(value == s or value.endswith("." + s) for s in provider_suffixes):
                    anomalies.append(f"CNAME to takeover-prone provider suffix: {value}")
            elif rtype == "TXT":
                if "v=spf1" in value and "+all" in value:
                    anomalies.append("TXT SPF policy contains +all (overly permissive)")
        deduped = []
        seen: set[str] = set()
        for item in anomalies:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        return deduped[:8]

    def _vt_cert_anomalies(self, attrs: Dict[str, Any]) -> List[str]:
        anomalies: List[str] = []
        cert = attrs.get("last_https_certificate") or {}
        if not isinstance(cert, dict):
            return anomalies

        subject = cert.get("subject") or {}
        issuer = cert.get("issuer") or {}
        if isinstance(subject, dict) and isinstance(issuer, dict):
            subj_cn = str(subject.get("CN") or "").strip().lower()
            issuer_cn = str(issuer.get("CN") or "").strip().lower()
            if subj_cn and issuer_cn and subj_cn == issuer_cn:
                anomalies.append("Certificate appears self-issued (issuer CN == subject CN)")
            if subj_cn.startswith("*."):
                anomalies.append(f"Wildcard certificate CN detected: {subj_cn}")

        valid_from = self._as_int(cert.get("validity", {}).get("not_before"), default=0) if isinstance(cert.get("validity"), dict) else 0
        valid_to = self._as_int(cert.get("validity", {}).get("not_after"), default=0) if isinstance(cert.get("validity"), dict) else 0
        if valid_from and valid_to and valid_to > valid_from:
            lifetime_days = int((valid_to - valid_from) / 86400)
            if lifetime_days > 398:
                anomalies.append(f"Certificate validity unusually long: {lifetime_days} days")
            try:
                if datetime.fromtimestamp(valid_to, timezone.utc) < datetime.now(timezone.utc):
                    anomalies.append("Certificate appears expired")
            except Exception:
                pass

        san = cert.get("extensions", {}).get("subject_alternative_name") if isinstance(cert.get("extensions"), dict) else None
        san_list = san if isinstance(san, list) else []
        san_values = [str(x).strip().lower() for x in san_list if str(x).strip()]
        if len(san_values) > 40:
            anomalies.append(f"Very large SAN list: {len(san_values)} entries")
        return anomalies[:8]

    async def _fetch_json(self, url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        try:
            response = await self.client.get(url, headers=headers or self.headers, timeout=self.timeout, follow_redirects=True)
        except Exception as exc:
            message = str(exc).strip()
            err = f"{exc.__class__.__name__}: {message}" if message else exc.__class__.__name__
            return {"ok": False, "status": None, "json": None, "error": self._redact_api_secrets(err)}

        payload: Optional[Any] = None
        if response.content:
            try:
                payload = response.json()
            except Exception:
                payload = None

        if response.status_code >= 400:
            detail = None
            if isinstance(payload, dict):
                detail = payload.get("error") or payload.get("message")
            if not detail:
                detail = f"HTTP {response.status_code}"
            return {
                "ok": False,
                "status": response.status_code,
                "json": payload if isinstance(payload, dict) else None,
                "error": self._redact_api_secrets(str(detail)),
            }

        return {"ok": True, "status": response.status_code, "json": payload if isinstance(payload, dict) else {}, "error": None}

    async def _virustotal_security(self) -> Dict[str, Any]:
        if not self.vt_key:
            return {"enabled": False}

        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}"
        fetch = await self._fetch_json(url, headers={"x-apikey": self.vt_key, "accept": "application/json"})
        if not fetch.get("ok"):
            return {
                "enabled": True,
                "ok": False,
                "level": "info",
                "summary": "VirusTotal check unavailable",
                "status_code": fetch.get("status"),
                "error": fetch.get("error"),
            }

        payload = fetch.get("json") or {}
        attrs = ((payload.get("data") or {}).get("attributes") or {}) if isinstance(payload, dict) else {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = self._as_int(stats.get("malicious"))
        suspicious = self._as_int(stats.get("suspicious"))
        harmless = self._as_int(stats.get("harmless"))
        undetected = self._as_int(stats.get("undetected"))
        reputation = self._as_int(attrs.get("reputation"), default=0)

        if malicious > 0:
            level = "critical"
        elif suspicious > 0:
            level = "warning"
        else:
            level = "ok"

        summary = (
            f"VT detections: malicious={malicious}, suspicious={suspicious}, "
            f"harmless={harmless}, undetected={undetected}"
        )

        categories_map = attrs.get("categories") or {}
        categories = []
        if isinstance(categories_map, dict):
            categories = sorted({str(v).strip() for v in categories_map.values() if str(v).strip()})
        dominant_category = self._vt_dominant_threat_category(attrs)
        dns_anomalies = self._vt_dns_anomalies(attrs)
        cert_anomalies = self._vt_cert_anomalies(attrs)

        total_votes = attrs.get("total_votes") or {}
        return {
            "enabled": True,
            "ok": True,
            "level": level,
            "summary": summary,
            "status_code": fetch.get("status"),
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "reputation": reputation,
            "categories": categories[:8],
            "dominant_threat_category": dominant_category,
            "dns_anomalies": dns_anomalies,
            "cert_anomalies": cert_anomalies,
            "tags": [str(t).strip() for t in (attrs.get("tags") or []) if str(t).strip()][:10],
            "last_analysis_date": self._iso_from_epoch(attrs.get("last_analysis_date")),
            "last_modification_date": self._iso_from_epoch(attrs.get("last_modification_date")),
            "votes_harmless": self._as_int(total_votes.get("harmless")),
            "votes_malicious": self._as_int(total_votes.get("malicious")),
        }

    async def _shodan_security(self, ips: List[str]) -> Dict[str, Any]:
        if not self.shodan_key:
            return {"enabled": False}
        if not ips:
            return {
                "enabled": True,
                "ok": False,
                "level": "info",
                "summary": "Shodan check skipped: no resolved IP",
                "error": None,
            }

        target_ip = str(ips[0]).strip()
        url = f"https://api.shodan.io/shodan/host/{target_ip}?key={self.shodan_key}"
        fetch = await self._fetch_json(url)
        if not fetch.get("ok"):
            status_code = fetch.get("status")
            if status_code == 404:
                return {
                    "enabled": True,
                    "ok": True,
                    "level": "info",
                    "summary": "No Shodan host data available for resolved IP",
                    "status_code": status_code,
                    "ip": target_ip,
                    "ports": [],
                    "vulns": [],
                }
            return {
                "enabled": True,
                "ok": False,
                "level": "info",
                "summary": "Shodan check unavailable",
                "status_code": status_code,
                "error": fetch.get("error"),
            }

        payload = fetch.get("json") or {}
        ports = sorted({self._as_int(p) for p in (payload.get("ports") or []) if self._as_int(p) > 0})
        vulns_obj = payload.get("vulns")
        vuln_entries = self._normalize_shodan_vulns(vulns_obj)
        vulns = [str(v.get("id") or "").strip() for v in vuln_entries if str(v.get("id") or "").strip()]

        hostnames = [str(h).strip() for h in (payload.get("hostnames") or []) if str(h).strip()]
        domains = [str(d).strip() for d in (payload.get("domains") or []) if str(d).strip()]
        affected_targets = sorted(set(hostnames + domains))

        risky_ports = {21, 23, 25, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}
        exposed = sorted(p for p in ports if p in risky_ports)
        if vulns:
            level = "critical"
            summary = f"Shodan reports {len(vulns)} known vulnerability identifiers"
        elif exposed:
            level = "warning"
            summary = f"Potentially exposed services on ports: {', '.join(str(p) for p in exposed)}"
        else:
            level = "ok"
            summary = f"Shodan host profile present ({len(ports)} open ports)"

        return {
            "enabled": True,
            "ok": True,
            "level": level,
            "summary": summary,
            "status_code": fetch.get("status"),
            "ip": str(payload.get("ip_str") or target_ip),
            "ports": ports[:30],
            "vulns": vulns[:30],
            "vuln_count": len(vulns),
            "vulns_ranked": vuln_entries[:50],
            "org": payload.get("org"),
            "isp": payload.get("isp"),
            "os": payload.get("os"),
            "hostnames": hostnames[:20],
            "domains": domains[:20],
            "affected_targets": affected_targets[:25],
            "tags": [str(t).strip() for t in (payload.get("tags") or []) if str(t).strip()][:10],
            "last_update": str(payload.get("last_update") or "").strip() or None,
            "risky_ports": exposed,
        }

    async def _threat_intel(self, dns_detail: Dict[str, Any]) -> Dict[str, Any]:
        ips = [str(ip).strip() for ip in ((dns_detail.get("a") or []) + (dns_detail.get("aaaa") or [])) if str(ip).strip()]
        vt_info, shodan_info = await asyncio.gather(self._virustotal_security(), self._shodan_security(ips))
        return {"virustotal": vt_info, "shodan": shodan_info}

    def _assess_security(
        self,
        https_chain: Dict[str, Any],
        tls_info: Dict[str, Any],
        tls_versions: Optional[List[str]],
        security_txt: Dict[str, Any],
        caa: Dict[str, Any],
        email_auth: Dict[str, Any],
        takeover: Dict[str, Any],
        open_redirect: Dict[str, Any],
        methods: Dict[str, Any],
        rate_waf: Dict[str, Any],
        threat_intel: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        checks: Dict[str, Dict[str, Any]] = {}
        catalog = load_server_versions_catalog(auto_update=True)

        set_cookie = https_chain.get("set_cookie") or []
        hsts = https_chain.get("hsts")
        sec_headers = https_chain.get("security_headers") or {}
        infra_headers = https_chain.get("infra_headers") or {}
        https_server = str(infra_headers.get("Server") or "").strip()
        server_assessment = assess_server_banner(https_server, catalog=catalog)
        body_sample = str(https_chain.get("body_sample") or "")
        mixed_count = len(re.findall(r"""(?i)\b(?:src|href)\s*=\s*["']http://""", body_sample))
        emails = sorted(set(self.EMAIL_RE.findall(body_sample)))

        # security.txt
        if security_txt.get("present"):
            checks["security_txt"] = {"level": "ok", "summary": "security.txt present"}
        else:
            checks["security_txt"] = {"level": "info", "summary": "security.txt missing or invalid", "detail": security_txt}

        # cookie flags
        if not set_cookie:
            checks["cookies"] = {"level": "info", "summary": "No Set-Cookie in final HTTPS response"}
        else:
            missing_secure = 0
            missing_httponly = 0
            missing_samesite = 0
            for c in set_cookie:
                lc = c.lower()
                if "secure" not in lc:
                    missing_secure += 1
                if "httponly" not in lc:
                    missing_httponly += 1
                if "samesite=" not in lc:
                    missing_samesite += 1
            level = "ok"
            if missing_secure > 0:
                level = "warning"
            elif missing_httponly > 0 or missing_samesite > 0:
                level = "info"
            checks["cookies"] = {
                "level": level,
                "summary": f"cookies={len(set_cookie)} missing_secure={missing_secure} missing_httponly={missing_httponly} missing_samesite={missing_samesite}",
            }

        # HSTS / headers
        header_issues: List[str] = []
        if not hsts:
            header_issues.append("missing HSTS")
        if not sec_headers.get("Content-Security-Policy"):
            header_issues.append("missing CSP")
        if not sec_headers.get("X-Frame-Options"):
            header_issues.append("missing X-Frame-Options")
        if not sec_headers.get("X-Content-Type-Options"):
            header_issues.append("missing X-Content-Type-Options")
        checks["headers"] = {
            "level": "ok" if not header_issues else "warning",
            "summary": "Header baseline looks good" if not header_issues else ", ".join(header_issues),
        }

        # TLS hygiene
        tls_issues: List[str] = []
        if not tls_info.get("strict_ok"):
            tls_issues.append("strict certificate verify failed")
        key_bits = tls_info.get("key_bits")
        key_type = tls_info.get("key_type")
        if key_type == "RSA" and isinstance(key_bits, int) and key_bits < 2048:
            tls_issues.append(f"weak RSA key size {key_bits}")
        if tls_info.get("self_signed"):
            tls_issues.append("self-signed certificate")
        supported_tls = [str(v).strip() for v in (tls_versions or []) if str(v).strip()]
        legacy_tls = [v for v in supported_tls if v in {"TLS 1.0", "TLS 1.1"}]
        if legacy_tls:
            tls_issues.append(f"legacy TLS supported: {', '.join(legacy_tls)}")
        checks["tls_hygiene"] = {
            "level": "ok" if not tls_issues else "warning",
            "summary": "TLS certificate hygiene looks good" if not tls_issues else ", ".join(tls_issues),
        }

        # CAA
        if caa.get("present"):
            checks["caa"] = {"level": "ok", "summary": f"CAA present ({len(caa.get('entries') or [])} entries)"}
        else:
            checks["caa"] = {"level": "info", "summary": "CAA not found"}

        spf = email_auth.get("spf") or {}
        checks["spf"] = {
            "level": str(spf.get("level") or "info"),
            "summary": str(spf.get("summary") or "SPF check unavailable"),
        }
        dmarc = email_auth.get("dmarc") or {}
        checks["dmarc"] = {
            "level": str(dmarc.get("level") or "info"),
            "summary": str(dmarc.get("summary") or "DMARC check unavailable"),
        }
        dkim = email_auth.get("dkim") or {}
        checks["dkim"] = {
            "level": str(dkim.get("level") or "info"),
            "summary": str(dkim.get("summary") or "DKIM check unavailable"),
        }

        # takeover hints
        if takeover.get("suspect"):
            checks["takeover"] = {"level": "warning", "summary": f"Potential takeover hint: {', '.join(takeover.get('suspect_targets') or [])}"}
        else:
            checks["takeover"] = {"level": "ok", "summary": "No takeover hint detected"}

        # open redirect
        if open_redirect.get("possible"):
            checks["open_redirect"] = {"level": "warning", "summary": "Potential open redirect behavior detected"}
        else:
            checks["open_redirect"] = {"level": "ok", "summary": "No open redirect behavior detected in safe probes"}

        # methods
        risky = methods.get("risky_methods") or []
        if risky:
            checks["methods"] = {"level": "warning", "summary": f"Potentially risky methods exposed: {', '.join(risky)}"}
        else:
            checks["methods"] = {"level": "ok", "summary": "No risky HTTP methods exposed"}

        # mixed content
        if mixed_count > 0:
            checks["mixed_content"] = {"level": "warning", "summary": f"Potential mixed content references: {mixed_count}"}
        else:
            checks["mixed_content"] = {"level": "ok", "summary": "No mixed content reference detected"}

        # rate-limit/WAF
        if rate_waf.get("rate_limited"):
            checks["rate_waf"] = {"level": "info", "summary": "Rate-limit behavior detected (HTTP 429)"}
        elif rate_waf.get("waf_flags"):
            checks["rate_waf"] = {"level": "info", "summary": f"WAF/challenge hint: {', '.join(rate_waf.get('waf_flags') or [])}"}
        else:
            checks["rate_waf"] = {"level": "ok", "summary": "No obvious WAF/rate-limit behavior in small burst"}

        # email exposure
        if emails:
            checks["emails"] = {"level": "info", "summary": f"Email-like strings found in response body: {len(emails)}"}
        else:
            checks["emails"] = {"level": "ok", "summary": "No email-like strings in sampled HTML body"}

        srv_status = str(server_assessment.get("status") or "unknown")
        if srv_status == "outdated":
            checks["server_version"] = {
                "level": "warning",
                "summary": f"Web server possibly outdated ({server_assessment.get('version')} < {server_assessment.get('latest')})",
            }
        elif srv_status == "up-to-date":
            checks["server_version"] = {"level": "ok", "summary": "Web server version is up-to-date"}
        elif srv_status == "advisory":
            checks["server_version"] = {"level": "info", "summary": "Web server version check is advisory for this product"}
        else:
            checks["server_version"] = {"level": "info", "summary": "Web server version could not be reliably evaluated"}

        ti = threat_intel or {}
        vt = ti.get("virustotal") or {}
        if vt.get("enabled"):
            if vt.get("ok"):
                checks["virustotal"] = {
                    "level": str(vt.get("level") or "info"),
                    "summary": str(vt.get("summary") or "VirusTotal data available"),
                }
            else:
                reason = str(vt.get("error") or vt.get("summary") or "request failed")
                checks["virustotal"] = {"level": "info", "summary": f"VirusTotal unavailable: {reason}"}

        shodan = ti.get("shodan") or {}
        if shodan.get("enabled"):
            if shodan.get("ok"):
                checks["shodan"] = {
                    "level": str(shodan.get("level") or "info"),
                    "summary": str(shodan.get("summary") or "Shodan data available"),
                }
            else:
                reason = str(shodan.get("error") or shodan.get("summary") or "request failed")
                checks["shodan"] = {"level": "info", "summary": f"Shodan unavailable: {reason}"}

        return {
            "checks": checks,
            "security_txt": security_txt,
            "caa": caa,
            "email_auth": email_auth,
            "takeover": takeover,
            "open_redirect": open_redirect,
            "methods": methods,
            "rate_waf": rate_waf,
            "emails": emails[:20],
            "mixed_content_count": mixed_count,
            "server_assessment": server_assessment,
            "server_versions_updated_at": catalog.get("updated_at"),
            "threat_intel": ti,
        }

    async def _useragent_compare(self) -> Dict[str, Any]:
        browser_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            )
        }
        default_probe, browser_probe = await asyncio.gather(
            self._request_detail(f"https://{self.domain}", headers=self.headers),
            self._request_detail(f"https://{self.domain}", headers=browser_headers),
        )
        return {"default": default_probe, "browser_like": browser_probe}

    def _extract_https_port(self, value: Optional[str]) -> Optional[int]:
        if not value:
            return None
        try:
            parsed = urlparse(value)
        except Exception:
            return None
        if parsed.scheme.lower() != "https":
            return None
        if parsed.port is None:
            return 443
        if parsed.port <= 0 or parsed.port > 65535:
            return None
        return int(parsed.port)

    def _redirect_https_port_from_chains(
        self,
        http_chain: Dict[str, Any],
        https_chain: Dict[str, Any],
        http_first_hop: Optional[Dict[str, Any]] = None,
    ) -> Optional[int]:
        candidates: List[str] = []
        for chain in (http_chain, https_chain, http_first_hop or {}):
            if not isinstance(chain, dict):
                continue
            url = chain.get("url")
            if isinstance(url, str) and url:
                candidates.append(url)
            for hop in chain.get("history") or []:
                if isinstance(hop, dict):
                    loc = hop.get("location")
                    app = hop.get("app_redirect")
                    if isinstance(loc, str) and loc:
                        candidates.append(loc)
                    if isinstance(app, str) and app:
                        candidates.append(app)
        for candidate in candidates:
            port = self._extract_https_port(candidate)
            if port and port != 443:
                return port
        return None

    async def _collect_verbose(self) -> Dict[str, Any]:
        """Gather extended diagnostics used by `--verbose`.

        How:
        - executes multiple independent probes concurrently via `asyncio.gather`
        - merges protocol/network/security data into one structured payload
        Where:
        - attached to scan result as `result["verbose"]` and rendered by
          `knockpy/output.py`.
        """
        (
            dns_detail,
            tls_detail,
            tls_versions,
            tcp_ports,
            http_chain,
            https_chain,
            ua_compare,
            http_first_hop,
            security_txt,
            caa_info,
            email_auth,
            takeover_hints,
            open_redirect,
            methods_info,
            rate_waf,
        ) = await asyncio.gather(
            self._dns_detail(),
            self._tls_handshake_detail(),
            self._check_tls_versions(),
            self._tcp_ports(),
            self._request_detail(f"http://{self.domain}", follow_redirects=True),
            self._request_detail(f"https://{self.domain}", follow_redirects=True),
            self._useragent_compare(),
            self._request_detail(f"http://{self.domain}", follow_redirects=False),
            self._security_txt_check(),
            self._caa_check(),
            self._email_auth_detail(),
            self._dns_takeover_hints(),
            self._open_redirect_probe(),
            self._http_methods_check(),
            self._rate_limit_waf_check(),
        )
        threat_intel = await self._threat_intel(dns_detail)
        verbose_data: Dict[str, Any] = {
            "dns": dns_detail,
            "tls": tls_detail,
            "tls_versions": tls_versions,
            "tcp_ports": tcp_ports,
            "http_chain": http_chain,
            "https_chain": https_chain,
            "ua_compare": ua_compare,
            "threat_intel": threat_intel,
            "security": self._assess_security(
                https_chain=https_chain,
                tls_info=tls_detail,
                tls_versions=tls_versions,
                security_txt=security_txt,
                caa=caa_info,
                email_auth=email_auth,
                takeover=takeover_hints,
                open_redirect=open_redirect,
                methods=methods_info,
                rate_waf=rate_waf,
                threat_intel=threat_intel,
            ),
        }

        redirect_port = self._redirect_https_port_from_chains(http_chain, https_chain, http_first_hop)
        if redirect_port:
            redirect_tls, redirect_tls_versions = await asyncio.gather(
                self._tls_handshake_detail(port=redirect_port),
                self._check_tls_versions(port=redirect_port),
            )
            verbose_data["redirect_tls"] = {
                "port": redirect_port,
                "handshake": redirect_tls,
                "versions": redirect_tls_versions,
            }

        return verbose_data

    async def _cert_fetch(self, resolved_ips: Optional[List[str]] = None) -> Tuple[Optional[bool], Optional[str], Optional[str], Optional[List[str]]]:
        """Collect certificate validity + metadata + supported TLS versions.

        Why two phases:
        - strict phase validates trust/hostname (real security state)
        - fallback phase extracts metadata even on validation failure, so the
          report remains actionable.
        """
        loop = asyncio.get_running_loop()

        def sync_cert() -> Tuple[Optional[bool], Optional[str], Optional[str]]:
            cert_ok = False
            expiry_iso: Optional[str] = None
            common_name: Optional[str] = None

            # Strict verification: chain trust + hostname verification.
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.domain) as tls_sock:
                        cert = tls_sock.getpeercert()
                        if cert:
                            not_after = cert.get("notAfter")
                            if not_after:
                                expiry_ts = ssl.cert_time_to_seconds(not_after)
                                expiry_date = datetime.fromtimestamp(expiry_ts, timezone.utc).date()
                                expiry_iso = expiry_date.isoformat()
                                cert_ok = expiry_date >= datetime.now(timezone.utc).date()

                            subject = cert.get("subject", ())
                            for rdns in subject:
                                for key, val in rdns:
                                    if key == "commonName":
                                        common_name = val
                                        break
                                if common_name:
                                    break
            except Exception:
                cert_ok = False

            # Best-effort metadata extraction even when strict verification fails.
            if expiry_iso is None or common_name is None:
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                        with ctx.wrap_socket(sock, server_hostname=self.domain) as tls_sock:
                            der_cert = tls_sock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert)
                    if common_name is None:
                        common_name = x509.get_subject().commonName or None
                    if expiry_iso is None:
                        not_after = x509.get_notAfter().decode("utf-8")
                        expiry_date = datetime.strptime(not_after, "%Y%m%d%H%M%SZ").date()
                        expiry_iso = expiry_date.isoformat()
                except Exception:
                    pass

            return cert_ok, expiry_iso, common_name

        async with self.cert_semaphore:
            is_valid, expiry, cn = await loop.run_in_executor(self.io_executor, sync_cert)

        tls_versions = await self._check_tls_versions(resolved_ips=resolved_ips)
        # Keep certificate validation status independent from protocol hardening.
        # Legacy TLS support is handled as a warning in output/report layers.
        return is_valid, expiry, cn, tls_versions

    def _tls_probe_cache_key(self, port: int, resolved_ips: Optional[List[str]]) -> str:
        if resolved_ips:
            normalized = ",".join(sorted({str(ip).strip() for ip in resolved_ips if str(ip).strip()}))
            if normalized:
                return f"{port}|{normalized}"
        return f"{port}|{self.domain.lower()}"

    async def _check_tls_versions(self, port: int = 443, resolved_ips: Optional[List[str]] = None) -> List[str]:
        loop = asyncio.get_running_loop()
        cache_key = self._tls_probe_cache_key(port, resolved_ips)
        now = time.monotonic()
        cached = self.TLS_PROBE_CACHE.get(cache_key)
        if cached and cached[0] > now:
            return list(cached[1])

        def sync_tls_check() -> List[str]:
            supported: List[str] = []
            tls_targets: List[Tuple[str, Any]] = []

            if hasattr(ssl, "TLSVersion"):
                if hasattr(ssl.TLSVersion, "TLSv1"):
                    tls_targets.append(("TLS 1.0", ssl.TLSVersion.TLSv1))
                if hasattr(ssl.TLSVersion, "TLSv1_1"):
                    tls_targets.append(("TLS 1.1", ssl.TLSVersion.TLSv1_1))
                if hasattr(ssl.TLSVersion, "TLSv1_2"):
                    tls_targets.append(("TLS 1.2", ssl.TLSVersion.TLSv1_2))
                if hasattr(ssl.TLSVersion, "TLSv1_3"):
                    tls_targets.append(("TLS 1.3", ssl.TLSVersion.TLSv1_3))

            def _probe_fixed_version(version: Any, allow_legacy_fallback: bool) -> bool:
                def _attempt(seclevel0: bool) -> bool:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    if seclevel0:
                        try:
                            # OpenSSL 3 may refuse TLS 1.0/1.1 at default security level.
                            # Lowering SECLEVEL for the probe lets us detect protocol support
                            # without changing the main scan client's TLS policy.
                            context.set_ciphers("DEFAULT:@SECLEVEL=0")
                        except Exception:
                            return False
                    context.minimum_version = version
                    context.maximum_version = version
                    with socket.create_connection((self.domain, int(port)), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=self.domain):
                            return True

                try:
                    return _attempt(seclevel0=False)
                except Exception:
                    if allow_legacy_fallback:
                        try:
                            return _attempt(seclevel0=True)
                        except Exception:
                            return False
                    return False

            for name, version in tls_targets:
                is_legacy = name in {"TLS 1.0", "TLS 1.1"}
                if _probe_fixed_version(version, allow_legacy_fallback=is_legacy):
                    supported.append(name)

            return supported

        supported_versions = await loop.run_in_executor(self.io_executor, sync_tls_check)
        if len(self.TLS_PROBE_CACHE) > 4096:
            # Bound memory usage during very large brute-force sessions.
            expired_keys = [k for k, v in self.TLS_PROBE_CACHE.items() if v[0] <= now]
            for key in expired_keys:
                self.TLS_PROBE_CACHE.pop(key, None)
            if len(self.TLS_PROBE_CACHE) > 4096:
                for key in list(self.TLS_PROBE_CACHE.keys())[:512]:
                    self.TLS_PROBE_CACHE.pop(key, None)
        self.TLS_PROBE_CACHE[cache_key] = (now + self.TLS_PROBE_TTL, list(supported_versions))
        return supported_versions

    async def scan(self) -> Optional[Dict[str, Any]]:
        """Execute full checks for the current domain and return normalized data.

        Used by `_run_async` worker tasks. Returns `None` when DNS resolution
        fails, otherwise returns protocol/cert data plus optional verbose details.
        """
        ips = await self._resolve_async(self.domain)
        if not ips:
            return None

        http, https = await asyncio.gather(
            self._http_check(f"http://{self.domain}"),
            self._http_check(f"https://{self.domain}"),
        )

        if http[0] and http[1] and not https[0]:
            location = http[1]
            if not location.startswith(("http://", "https://")):
                location = "http://" + location
            redirected = location.split("://", 1)[1].split("/")[0]
            https = await self._http_check(f"https://{redirected}")

        cert = (None, None, None, None)
        if https[0]:
            cert = await self._cert_fetch(resolved_ips=ips)

        takeover = await self._takeover_check(http, https)

        result = {
            "domain": self.domain,
            "ip": ips,
            "http": list(http),
            "https": list(https),
            "cert": list(cert),
        }
        if takeover:
            result["takeover"] = takeover
            takeover_status = str(takeover.get("status") or "")
            provider = str(takeover.get("provider") or "unknown")
            cname = str(takeover.get("cname") or "-")
            if takeover_status == "likely":
                result.setdefault("scan_notes", []).append(
                    f"Takeover risk: likely ({provider}) via CNAME {cname}."
                )
            elif takeover_status == "possible":
                result.setdefault("scan_notes", []).append(
                    f"Takeover risk: possible ({provider}) via CNAME {cname}."
                )
        if self.verbose:
            result["verbose"] = await self._collect_verbose()
        return result


async def _run_async(
    domains: List[str],
    dns: Optional[str],
    useragent: Optional[str],
    timeout: Optional[float],
    threads: Optional[int],
    recon: bool,
    bruteforce: bool,
    wordlist: Optional[str],
    verbose: bool = False,
    enable_axfr: bool = True,
    api_key_virustotal: Optional[str] = None,
    api_key_shodan: Optional[str] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> Union[List[dict], dict, None]:
    """Main orchestrator used by both CLI and Python API.

    Flow:
    1. normalize/expand target set (recon + bruteforce)
    2. optionally run AXFR check on root domain
    3. run scanner(s) with bounded concurrency
    4. attach scan notes/AXFR metadata and return normalized result(s)
    """
    if not domains:
        return None

    base = domains[0]
    effective_useragent = pick_user_agent(useragent)
    # Phase 1: expand targets before scanner execution.
    if recon or bruteforce:
        expanded: List[str] = []
        if recon:
            recon_engine = Recon(
                base,
                timeout=(timeout or 3.0),
                max_concurrency=40,
                useragent=effective_useragent,
                virustotal_key=api_key_virustotal,
                shodan_key=api_key_shodan,
            )
            expanded.extend(await recon_engine.start())
        if bruteforce:
            brute_engine = Bruteforce(base, wordlist)
            expanded.extend(brute_engine.start())
        domains = list(OrderedDict.fromkeys(domains + expanded))

    timeout_value = timeout or 3.0
    axfr_info: Optional[Dict[str, Any]] = None
    # Phase 2: run root-domain AXFR probe once and attach metadata to results.
    if enable_axfr:
        axfr_timeout = max(3.0, timeout_value * 2.0 + 1.0)
        try:
            axfr_info = await asyncio.wait_for(_axfr_check_root(base, dns, timeout_value), timeout=axfr_timeout)
        except asyncio.TimeoutError:
            axfr_info = {"domain": base, "status": "timeout", "checks": [], "error": f"Global AXFR timeout after {axfr_timeout:.1f}s"}

    def _axfr_note(axfr: Dict[str, Any]) -> str:
        status = str(axfr.get("status") or "unknown")
        if status == "allowed":
            ns = axfr.get("allowed_ns") or "-"
            count = axfr.get("record_count") or "-"
            return f"AXFR on root domain: allowed via {ns} (records: {count})."
        checks = axfr.get("checks") or []
        return f"AXFR on root domain: {status} ({len(checks)} NS checked)."

    def _inject_axfr(result_obj: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]], axfr: Optional[Dict[str, Any]]) -> None:
        if not axfr or not result_obj:
            return
        note = _axfr_note(axfr)
        if isinstance(result_obj, dict):
            notes = result_obj.get("scan_notes") or []
            if note not in notes:
                notes.append(note)
            result_obj["scan_notes"] = notes
            result_obj["axfr"] = axfr
            return
        if isinstance(result_obj, list):
            target = None
            for item in result_obj:
                if str(item.get("domain") or "").lower() == base.lower():
                    target = item
                    break
            if target is None and result_obj:
                target = result_obj[0]
            if isinstance(target, dict):
                notes = target.get("scan_notes") or []
                if note not in notes:
                    notes.append(note)
                target["scan_notes"] = notes
                target["axfr"] = axfr

    max_workers = threads or 250
    io_workers = max(64, min(512, max_workers * 2))
    timeout_cfg = httpx.Timeout(timeout_value)
    limits_cfg = httpx.Limits(
        max_connections=max(100, max_workers * 2),
        max_keepalive_connections=max(50, max_workers),
    )

    # Fast path for single target: keep behavior compatible with direct checks.
    if len(domains) == 1:
        with ThreadPoolExecutor(max_workers=io_workers) as io_executor:
            async with httpx.AsyncClient(
                http2=True,
                verify=False,
                timeout=timeout_cfg,
                limits=limits_cfg,
            ) as client:
                scanner = AsyncScanner(
                    domains[0],
                    client=client,
                    dns_server=dns,
                    useragent=effective_useragent,
                    timeout=timeout_value,
                    root_domain=base,
                    io_executor=io_executor,
                    verbose=verbose,
                    api_key_virustotal=api_key_virustotal,
                    api_key_shodan=api_key_shodan,
                )
                result = await scanner.scan()
                if result is None and not recon and not bruteforce:
                    fallback_domain = _www_fallback_domain(domains[0])
                    if fallback_domain:
                        fallback_scanner = AsyncScanner(
                            fallback_domain,
                            client=client,
                            dns_server=dns,
                            useragent=effective_useragent,
                            timeout=timeout_value,
                            root_domain=base,
                            io_executor=io_executor,
                            verbose=verbose,
                            api_key_virustotal=api_key_virustotal,
                            api_key_shodan=api_key_shodan,
                        )
                        result = await fallback_scanner.scan()
                        if result is not None:
                            result["scan_notes"] = [
                                f"No results for {domains[0]}; tried fallback {fallback_domain}."
                            ]
                if progress_callback:
                    progress_callback(1, 1)
                _inject_axfr(result, axfr_info)
                return result

    cert_semaphore = asyncio.Semaphore(50)

    # Multi-target path with bounded concurrency and shared HTTP client.
    with ThreadPoolExecutor(max_workers=io_workers) as io_executor:
        async with httpx.AsyncClient(
            http2=True,
            verify=False,
            timeout=timeout_cfg,
            limits=limits_cfg,
        ) as client:
            queue: "asyncio.Queue[Optional[str]]" = asyncio.Queue()
            for domain in domains:
                queue.put_nowait(domain)

            worker_count = max(1, min(max_workers, len(domains)))
            for _ in range(worker_count):
                queue.put_nowait(None)

            results: List[Dict[str, Any]] = []
            total = len(domains)
            done = 0
            done_lock = asyncio.Lock()

            async def worker() -> None:
                nonlocal done
                while True:
                    scan_domain = await queue.get()
                    try:
                        if scan_domain is None:
                            return
                        scanner = AsyncScanner(
                            scan_domain,
                            client=client,
                            dns_server=dns,
                            useragent=effective_useragent,
                            timeout=timeout_value,
                            cert_semaphore=cert_semaphore,
                            root_domain=base,
                            io_executor=io_executor,
                            verbose=verbose,
                            api_key_virustotal=api_key_virustotal,
                            api_key_shodan=api_key_shodan,
                        )
                        result = await scanner.scan()
                        if result:
                            results.append(result)
                    finally:
                        if scan_domain is not None:
                            async with done_lock:
                                done += 1
                                if progress_callback:
                                    progress_callback(done, total)
                        queue.task_done()

            workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
            await queue.join()
            await asyncio.gather(*workers)

    _inject_axfr(results, axfr_info)
    return results


def _run_coro_sync(coro: Any) -> Any:
    """Run async code from sync callers (CLI and public API).

    If already inside an event loop, execute in a helper thread to avoid
    `RuntimeError: asyncio.run() cannot be called from a running event loop`.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    outcome: Dict[str, Any] = {}

    def target() -> None:
        try:
            outcome["result"] = asyncio.run(coro)
        except Exception as exc:  # pragma: no cover - fallback path
            outcome["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join()

    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("result")


def KNOCKPY(
    domain: Union[str, Iterable[str]],
    dns: Optional[str] = None,
    useragent: Optional[str] = None,
    timeout: Optional[float] = None,
    threads: Optional[int] = None,
    recon: bool = False,
    bruteforce: bool = False,
    wordlist: Optional[str] = None,
    silent: bool = False,
    verbose: bool = False,
    enable_axfr: bool = True,
    api_key_virustotal: Optional[str] = None,
    api_key_shodan: Optional[str] = None,
) -> Union[List[dict], dict, None]:
    """Public synchronous Python API entrypoint.

    Example:
    `KNOCKPY("example.com", recon=True, bruteforce=True, verbose=False)`
    """
    if isinstance(domain, str):
        domains = [domain]
    else:
        domains = list(domain)

    return _run_coro_sync(
        _run_async(
            domains,
            dns,
            useragent,
            timeout,
            threads,
            recon,
            bruteforce,
            wordlist,
            verbose=verbose,
            enable_axfr=enable_axfr,
            api_key_virustotal=api_key_virustotal,
            api_key_shodan=api_key_shodan,
        )
    )
