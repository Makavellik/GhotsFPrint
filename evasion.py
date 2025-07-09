import aiohttp
import random
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import socket
import ssl
import json
import re
import base64
import time
import whois
from datetime import datetime
import logging
from functools import lru_cache
import ipaddress
import uuid
import hashlib


# User agents y headers para evasión ultra furtiva, con rotación dinámica
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.111 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "curl/7.88.1",
]

BASE_HEADERS_LIST = [
    {
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Connection": "keep-alive",
        "Referer": "https://www.google.com/",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    },
    {
        "Accept-Language": "es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
        "Referer": "https://www.bing.com/",
        "DNT": "1",
    },
    {
        "Accept-Language": "en-US,en;q=0.7",
        "Accept-Encoding": "gzip, br",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Connection": "keep-alive",
        "Referer": "https://duckduckgo.com/",
        "DNT": "1",
    }
]


def select_random_headers():
    # Elegimos una base súper random y la clonamos para no tocar el original
    base = random.choice(BASE_HEADERS_LIST).copy()

    # User-Agent vibrante y renovado
    base["User-Agent"] = random.choice(USER_AGENTS)

    # Identificadores únicos y frescos para trazabilidad
    base["X-Request-ID"] = ''.join(random.choices('abcdef0123456789', k=16))
    base["X-Trace-ID"] = ''.join(random.choices('abcdef0123456789', k=16))

    # Agregar un timestamp UTC para frescura temporal (formato ISO8601)
    base["X-Timestamp"] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

    # Generar un UUIDv4 para identificación única extendida
    base["X-Session-UUID"] = str(uuid.uuid4())

    # Firmar los headers con hash SHA256 de User-Agent + Request-ID para integridad y poder irrepetible
    signature_source = base["User-Agent"] + base["X-Request-ID"]
    signature_hash = hashlib.sha256(signature_source.encode('utf-8')).hexdigest()
    base["X-Request-Signature"] = signature_hash

    # Headers adicionales randomizados para camuflaje avanzado
    # Ejemplo: Randomizar el header "Accept-Language" de una lista plausible
    ACCEPT_LANGUAGES = ['en-US,en;q=0.9', 'es-ES,es;q=0.9', 'fr-FR,fr;q=0.9', 'de-DE,de;q=0.9']
    base["Accept-Language"] = random.choice(ACCEPT_LANGUAGES)

    # Añadir header personalizado para detección futura (puede servir para debugging)
    base["X-Custom-Power"] = "CosmicForceLevel-9999"

    return base


async def fetch_html(url, headers=None, max_redirects=5, timeout=20, retries=3, proxy=None, verbose=False):
    """
    Fetch HTML async con manejo avanzado de redirects, reintentos, proxy y evasión.

    Parámetros:
        url (str): URL a consultar.
        headers (dict): Headers personalizados (si no, se usa uno random).
        max_redirects (int): Máximo número de redirects.
        timeout (int): Timeout en segundos.
        retries (int): Reintentos en caso de error.
        proxy (str): Proxy opcional (http://ip:port).
        verbose (bool): Mostrar logs detallados.

    Retorna:
        Tuple (content, headers, cookies, final_url, status_code)
    """

    if headers is None:
        headers = {}

    # Asignar User-Agent random si no existe
    if 'User-Agent' not in headers:
        headers['User-Agent'] = random.choice(USER_AGENTS)

    attempt = 0
    backoff_base = 1.0
    current_url = url

    while attempt <= retries:
        try:
            timeout_cfg = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(headers=headers, timeout=timeout_cfg) as session:
                for _ in range(max_redirects):
                    if verbose:
                        logger.info(f"[Intento {attempt+1}] GET {current_url}")

                    async with session.get(current_url, allow_redirects=False, proxy=proxy) as response:
                        # Manejo de redirects
                        if response.status in {301, 302, 303, 307, 308}:
                            location = response.headers.get('Location')
                            if not location:
                                if verbose:
                                    logger.warning(f"No Location header en redirect {response.status}")
                                break
                            # Normalizar URL relativa
                            location = urljoin(current_url, location)
                            current_url = location
                            if verbose:
                                logger.info(f"Redirect a {current_url}")
                            continue

                        # Obtener contenido de forma segura ignorando errores de decoding
                        content = await response.text(errors='ignore')

                        # Limpiar cookies (solo devolver lo esencial)
                        cookies = {key: morsel.value for key, morsel in response.cookies.items()}

                        if verbose:
                            logger.info(f"Respuesta exitosa [{response.status}] de {current_url}")

                        return content, dict(response.headers), cookies, current_url, response.status

            # Si excede redirects o falla, status 599
            if verbose:
                logger.error(f"Max redirects ({max_redirects}) alcanzados sin éxito.")
            return "", {}, {}, current_url, 599

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            if verbose:
                logger.warning(f"[Intento {attempt+1}] Error: {e}")

        except Exception as e:
            if verbose:
                logger.error(f"[Intento {attempt+1}] Excepción inesperada: {e}")

        # Backoff exponencial + jitter para evasión
        wait_time = backoff_base * (2 ** attempt) + random.uniform(0, 0.5)
        if verbose:
            logger.info(f"Esperando {wait_time:.2f}s antes de reintentar...")
        await asyncio.sleep(wait_time)
        attempt += 1

    # Último fallback: retorno vacío con error
    if verbose:
        logger.error(f"No se pudo obtener contenido de {url} después de {retries} intentos.")
    return "", {}, {}, current_url, 599



# Configuración básica de logging cósmico
logging.basicConfig(level=logging.INFO, format='[dns_lookup] %(levelname)s: %(message)s')

# Cache cósmica para acelerar consultas repetidas
@lru_cache(maxsize=128)
def _cached_getaddrinfo(hostname):
    return socket.getaddrinfo(hostname, None)

def dns_lookup(hostname, retries=4, timeout=3, backoff_base=0.5, jitter=0.3, ipv6=True):
    """
    DNS Lookup superpotenciado y evasivo.
    
    :param hostname: dominio a resolver
    :param retries: cantidad de reintentos en caso de fallo
    :param timeout: timeout por intento en segundos (socket.setdefaulttimeout)
    :param backoff_base: base para backoff exponencial (en segundos)
    :param jitter: factor para agregar aleatoriedad al backoff (0 a 1)
    :param ipv6: si True incluye direcciones IPv6, si False solo IPv4
    :return: lista única de IPs
    """
    socket.setdefaulttimeout(timeout)
    attempt = 0

    while attempt < retries:
        try:
            logging.info(f"Intento {attempt+1} para resolver {hostname}")
            
            # Usar cache cósmica para acelerar si ya fue consultado antes
            addr_info = _cached_getaddrinfo(hostname)

            ips = set()
            for result in addr_info:
                family, _, _, _, sockaddr = result
                ip = sockaddr[0]
                if not ipv6 and family == socket.AF_INET6:
                    continue  # Saltar IPv6 si no queremos
                ips.add(ip)
            
            if ips:
                logging.info(f"IPs encontradas: {ips}")
                return list(ips)
            else:
                logging.warning(f"No se encontraron IPs para {hostname}")
                return []

        except socket.gaierror as e:
            logging.warning(f"Error de resolución (intento {attempt+1}): {e}")
        except socket.timeout as e:
            logging.warning(f"Timeout en resolución (intento {attempt+1}): {e}")
        except Exception as e:
            logging.error(f"Error inesperado (intento {attempt+1}): {e}")

        # Backoff exponencial con jitter para evasión cósmica
        base_wait = backoff_base * (2 ** attempt)
        wait_time = base_wait + random.uniform(0, jitter * base_wait)
        logging.info(f"Esperando {wait_time:.2f}s antes del próximo intento...")
        time.sleep(wait_time)
        attempt += 1

    logging.error(f"No se pudo resolver {hostname} después de {retries} intentos.")
    return []

# Configuración básica de logging
logger = logging.getLogger("reverse_dns")
logging.basicConfig(level=logging.INFO, format='[reverse_dns] %(levelname)s: %(message)s')

def reverse_dns(ip, timeout=2.0, retries=3, verbose=False, backoff_base=0.5, jitter=0.3):
    """
    Realiza búsqueda DNS inversa con reintentos, timeout y evasión avanzada.

    Parámetros:
        ip (str): Dirección IP a consultar.
        timeout (float): Tiempo de espera por intento en segundos.
        retries (int): Número de reintentos.
        verbose (bool): Mostrar info detallada en consola.
        backoff_base (float): Tiempo base para backoff exponencial.
        jitter (float): Factor de variabilidad para evitar patrones.

    Retorna:
        dict: {
          "hostname": str|None,
          "ip": str,
          "elapsed": float (segundos),
          "success": bool
        }
    """
    # Validar IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        if verbose:
            logger.warning(f"IP inválida: {ip}")
        return {"hostname": None, "ip": ip, "elapsed": 0.0, "success": False}

    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    attempt = 0

    while attempt <= retries:
        start_time = time.perf_counter()
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            elapsed = time.perf_counter() - start_time
            if verbose:
                logger.info(f"[Intento {attempt+1}] Hostname resuelto: {hostname} (tiempo: {elapsed:.3f}s)")
            socket.setdefaulttimeout(original_timeout)
            return {"hostname": hostname, "ip": ip, "elapsed": elapsed, "success": True}

        except socket.herror as e:
            if verbose:
                logger.warning(f"[Intento {attempt+1}] Error de resolución DNS inversa: {e}")
        except socket.timeout:
            if verbose:
                logger.warning(f"[Intento {attempt+1}] Timeout ({timeout}s) agotado.")
        except Exception as e:
            if verbose:
                logger.error(f"[Intento {attempt+1}] Excepción inesperada: {e}")

        # Backoff exponencial con jitter
        base_wait = backoff_base * (2 ** attempt)
        wait_time = base_wait + random.uniform(0, jitter * base_wait)
        if verbose:
            logger.info(f"Esperando {wait_time:.2f}s antes del próximo intento...")
        time.sleep(wait_time)
        attempt += 1

    socket.setdefaulttimeout(original_timeout)
    if verbose:
        logger.error(f"No se pudo resolver el hostname para la IP {ip} después de {retries} intentos.")
    return {"hostname": None, "ip": ip, "elapsed": 0.0, "success": False}



def clean_whois_string(s):
    if isinstance(s, list):
        return [clean_whois_string(x) for x in s]
    if not s:
        return None
    # Limpieza básica: quitar espacios extras, saltos, caracteres no imprimibles
    s = str(s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        
        # Extraer datos importantes y limpiar
        result = {
            "domain_name": clean_whois_string(w.domain_name),
            "registrar": clean_whois_string(w.registrar),
            "whois_server": clean_whois_string(w.whois_server),
            "referral_url": clean_whois_string(w.referral_url),
            "updated_date": clean_whois_string(w.updated_date),
            "creation_date": clean_whois_string(w.creation_date),
            "expiration_date": clean_whois_string(w.expiration_date),
            "name_servers": clean_whois_string(w.name_servers),
            "status": clean_whois_string(w.status),
            "emails": clean_whois_string(w.emails),
            "dnssec": clean_whois_string(w.dnssec),
            # Contactos administrativos y técnicos (si existen)
            "registrant": clean_whois_string(w.get('registrant')),
            "admin": clean_whois_string(w.get('admin')),
            "tech": clean_whois_string(w.get('tech')),
        }
        
        # Filtrar claves con None o vacías para no saturar
        result = {k: v for k, v in result.items() if v not in (None, '', [], {})}
        
        return {"whois_data": result}
    except Exception as e:
        # Retorna error sin romper el flow
        return {"whois_data": None, "error": str(e)}

def detectcdn(headers, custom_signatures=None):
    """
    Detecta si una respuesta HTTP utiliza una CDN basada en los encabezados proporcionados.

    Args:
        headers (dict): Encabezados HTTP de la respuesta.
        custom_signatures (list, optional): Lista adicional de firmas de CDNs a detectar.

    Returns:
        bool: True si se detecta el uso de una CDN, False en caso contrario.
    """
    # Lista robusta y extensible de firmas de CDNs comunes
    cdn_signatures = {
        "cloudflare", "akamai", "fastly", "maxcdn", "cdn.jsdelivr.net", "edgecast",
        "cachefly", "netlify", "vercel", "githubusercontent", "stackpath", "cdnsun",
        "quantil", "belugacdn", "bunnycdn", "keycdn", "azureedge", "amazon cloudfront",
        "google", "incapsula", "revcdn", "section.io", "gcore", "hostry", "bitgravity",
        "zenedge", "cdn77", "swarmify", "jsdelivr", "digitalocean spaces"
    }

    # Agrega firmas personalizadas si las hay
    if custom_signatures:
        cdn_signatures.update(s.lower() for s in custom_signatures)

    # Cabeceras comúnmente utilizadas por CDNs
    header_keys_to_check = [
        "Server", "Via", "CF-Ray", "X-Cache", "X-CDN", "X-Powered-By",
        "X-Amz-Cf-Id", "X-Edge-Location", "X-Served-By", "X-Fastly-Request-ID",
        "X-Akamai-Transformed", "X-CDN-Forward"
    ]

    # Combina y normaliza los valores relevantes
    combined_header_data = " ".join(
        str(headers.get(header, "")).lower() for header in header_keys_to_check
    )

    # Revisión explícita para evitar falsos negativos
    for signature in cdn_signatures:
        if signature in combined_header_data:
            return True

    return False


def analyze_cookies(cookies):
    cookies_info = []

    def is_base64(s):
        try:
            if isinstance(s, str):
                base64.b64decode(s + '==', validate=True)
                return True
        except Exception:
            return False
        return False

    for key, cookie in cookies.items():
        # Adaptar a cookie como string si no es objeto
        if isinstance(cookie, str):
            value = cookie
            meta = {}
        elif hasattr(cookie, 'value'):
            value = cookie.value or ""
            meta = {
                "expires": getattr(cookie, "expires", None),
                "secure": getattr(cookie, "secure", False),
                "httponly": getattr(cookie, "httponly", False),
                "samesite": getattr(cookie, "samesite", None),
                "domain": getattr(cookie, "domain", ""),
                "path": getattr(cookie, "path", None),
            }
        elif isinstance(cookie, dict):
            value = cookie.get("value", "")
            meta = cookie
        else:
            value = str(cookie)
            meta = {}

        value_len = len(value)

        # Detección de codificación
        is_val_base64 = is_base64(value)
        is_val_hex = bool(re.fullmatch(r'[0-9a-fA-F]+', value)) and value_len % 2 == 0

        # Flags
        expires = meta.get("expires")
        is_session_cookie = expires is None
        secure = meta.get("secure", False)
        httponly = meta.get("httponly", False)
        samesite = meta.get("samesite")
        samesite_strict = samesite and samesite.lower() == 'strict'
        samesite_lax = samesite and samesite.lower() == 'lax'
        samesite_none = samesite and samesite.lower() == 'none'
        domain = meta.get("domain", "")
        cross_site = domain.startswith('.') if domain else False

        suspicious_name = bool(re.search(r'(session|auth|token|sess|csrf|id|tracking|user|uid|secure)', key, re.I))
        suspicious_value_pattern = bool(re.search(r'^[A-Za-z0-9_\-\.=]+$', value)) and (is_val_base64 or is_val_hex)
        large_cookie = (value_len > 1024)

        info = {
            "name": key,
            "value_len": value_len,
            "is_value_base64": is_val_base64,
            "is_value_hex": is_val_hex,
            "domain": domain or None,
            "cross_site_possible": cross_site,
            "path": meta.get("path"),
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite,
            "samesite_strict": samesite_strict,
            "samesite_lax": samesite_lax,
            "samesite_none": samesite_none,
            "expires": expires,
            "is_session_cookie": is_session_cookie,
            "flags": {
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite,
            },
            "suspicious_name": suspicious_name,
            "suspicious_value_pattern": suspicious_value_pattern,
            "large_cookie": large_cookie,
            "comments": [
                "Session cookie" if is_session_cookie else "Persistent cookie",
                "Potential cross-site" if cross_site else "Same-site cookie",
                "Suspicious name pattern" if suspicious_name else "Name looks normal",
                "Value looks encoded" if (is_val_base64 or is_val_hex) else "Value looks plain",
                "Large cookie size" if large_cookie else "Cookie size normal",
            ]
        }

        cookies_info.append(info)

    return cookies_info


def detect_technologies(html, headers):
    detected = set()
    tech_map = {
        "wordpress": re.compile(r'wp-content|wp-includes|wordpress', re.I),
        "drupal": re.compile(r'drupal\.settings|Drupal', re.I),
        "joomla": re.compile(r'Joomla!', re.I),
        "shopify": re.compile(r'Shopify', re.I),
        "express": re.compile(r'X-Powered-By: Express', re.I),
        "php": re.compile(r'X-Powered-By: PHP', re.I),
        "nginx": re.compile(r'nginx', re.I),
        "apache": re.compile(r'apache', re.I),
        "react": re.compile(r'React|__REACT_DEVTOOLS_GLOBAL_HOOK__', re.I),
        "vue.js": re.compile(r'Vue\.config|Vue', re.I),
        "angular": re.compile(r'ng-version', re.I),
        "django": re.compile(r'Django', re.I),
        "ruby on rails": re.compile(r'Ruby on Rails', re.I),
        "flask": re.compile(r'Flask', re.I),
        "cloudflare": re.compile(r'cloudflare', re.I),
        "aws": re.compile(r'AmazonS3|Amazon CloudFront', re.I),
        "gcp": re.compile(r'Google Frontend', re.I),
        "azure": re.compile(r'Azure', re.I),
        "fastly": re.compile(r'Fastly', re.I),
    }

    for tech, pattern in tech_map.items():
        if pattern.search(html) or pattern.search(str(headers)):
            detected.add(tech)

    return list(detected)

def analyze_security_headers(headers):
    """
    Analiza encabezados de seguridad con interpretación extendida y simbiótica.

    Retorna un diccionario enriquecido por cada header encontrado, con estado, valor, e interpretación.
    """

    def interpret_header(key, value):
        key_lower = key.lower()
        comments = []
        status = "OK"
        
        if key_lower == "content-security-policy":
            if "default-src" not in value:
                status = "⚠️"
                comments.append("Falta 'default-src' en CSP (riesgo de inyección).")
            if "'unsafe-inline'" in value:
                status = "⚠️"
                comments.append("Uso de 'unsafe-inline' detectado (riesgo XSS).")

        elif key_lower == "strict-transport-security":
            if "max-age" in value:
                try:
                    max_age = int(re.search(r'max-age=(\d+)', value).group(1))
                    if max_age < 15552000:
                        status = "⚠️"
                        comments.append("max-age demasiado bajo (recomendado: ≥ 6 meses).")
                except:
                    status = "❌"
                    comments.append("max-age no se pudo interpretar.")
            else:
                status = "❌"
                comments.append("Falta max-age en HSTS.")

        elif key_lower == "x-frame-options":
            if value.lower() not in ["deny", "sameorigin"]:
                status = "⚠️"
                comments.append("Valor X-Frame-Options débil (usa 'DENY' o 'SAMEORIGIN').")

        elif key_lower == "x-content-type-options":
            if value.lower() != "nosniff":
                status = "❌"
                comments.append("Debe usar 'nosniff' para prevenir ataques MIME-type.")

        elif key_lower == "referrer-policy":
            if value.lower() not in ["strict-origin", "strict-origin-when-cross-origin", "no-referrer"]:
                status = "⚠️"
                comments.append("Política Referrer no es la más estricta.")

        elif key_lower == "permissions-policy" or key_lower == "feature-policy":
            if "geolocation" not in value and "camera" not in value:
                comments.append("Política podría estar incompleta (falta restricción de sensores).")

        elif key_lower == "expect-ct":
            if "enforce" not in value:
                comments.append("No aplica políticas estrictas en Expect-CT.")

        return {
            "value": value,
            "status": status,
            "comments": comments
        }

    security_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Feature-Policy",  # legacy
        "Expect-CT"
    ]

    analyzed = {}

    for key in security_headers:
        val = headers.get(key)
        if val:
            analyzed[key] = interpret_header(key, val)

    return analyzed


def parse_json_ld(soup):
    data = []
    for script in soup.find_all('script', type='application/ld+json'):
        try:
            content = script.string
            if content:
                parsed = json.loads(content)
                data.append(parsed)
        except Exception:
            continue
    return data


def analyze_inline_scripts(soup):
    inline_scripts = []
    suspicious_patterns = ['gtag', 'ga(', 'mixpanel', 'analytics', 'fbq', 'dataLayer', 'pixel', 'matomo', 'hotjar', 'crisp']
    found = set()
    for script in soup.find_all('script'):
        if script.string:
            s = script.string.lower()
            for pattern in suspicious_patterns:
                if pattern in s:
                    found.add(pattern)
            inline_scripts.append(script.string[:100])
    return list(found), inline_scripts[:10]


def analyze_ssl_certificate(hostname, port=443, timeout=7):
    """
    Realiza una inspección profunda del certificado SSL/TLS con poder simbiótico.
    Analiza sujeto, emisor, fechas, cifrado, validez y más.

    :param hostname: Dominio a analizar.
    :param port: Puerto SSL (por defecto 443).
    :param timeout: Tiempo máximo de espera.
    :return: Diccionario ultra enriquecido con detalles del certificado.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol_version = ssock.version()

                # Extraer fechas y validarlas
                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')
                not_before_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                not_after_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.utcnow()
                days_valid = (not_after_dt - not_before_dt).days
                days_remaining = (not_after_dt - now).days

                # Análisis de emisor
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))

                # Evaluar si es autofirmado
                self_signed = issuer == subject

                # Extraer SANs (Subject Alternative Names)
                alt_names = []
                for ext in cert.get("subjectAltName", []):
                    if ext[0] == "DNS":
                        alt_names.append(ext[1])

                return {
                    "cert_subject": subject,
                    "cert_issuer": issuer,
                    "self_signed": self_signed,
                    "not_before": not_before,
                    "not_after": not_after,
                    "valid_for_days": days_valid,
                    "days_until_expiry": max(0, days_remaining),
                    "expired": days_remaining < 0,
                    "protocol_version": protocol_version,
                    "cipher_suite": {
                        "name": cipher[0] if cipher else None,
                        "protocol": cipher[1] if cipher else None,
                        "bits": cipher[2] if cipher else None
                    },
                    "san_list": alt_names,
                    "hostname_validated": hostname in alt_names,
                }

    except ssl.SSLError as e:
        return {"error": f"SSL Error: {str(e)}"}
    except socket.timeout:
        return {"error": "Connection timed out"}
    except socket.gaierror:
        return {"error": "Hostname could not be resolved"}
    except Exception as e:
        return {"error": str(e)}



async def measure_response_times(
    url,
    headers=None,
    samples=3,
    timeout=20,
    delay_range=(0.1, 0.3),
    validate_status=True,
    return_details=False
):
    """
    Mide el tiempo de respuesta promedio de una URL mediante múltiples solicitudes asincrónicas.

    Args:
        url (str): La URL a medir.
        headers (dict, opcional): Encabezados HTTP personalizados.
        samples (int): Número de veces que se enviará la solicitud.
        timeout (int o float): Tiempo máximo de espera por cada solicitud.
        delay_range (tuple): Rango de espera aleatoria entre solicitudes (min, max).
        validate_status (bool): Si es True, solo considera respuestas con status 200 como válidas.
        return_details (bool): Si es True, devuelve una lista de dicts con detalles por muestra.

    Returns:
        list: Lista de tiempos (float en segundos o None si hubo error),
              o lista de dicts detallados si `return_details` es True.
    """
    results = []

    headers = headers or {}

    timeout_config = aiohttp.ClientTimeout(total=timeout)

    async with aiohttp.ClientSession(headers=headers, timeout=timeout_config) as session:
        for i in range(samples):
            result = {"sample": i + 1, "time": None, "status": None, "error": None}
            start = time.perf_counter()

            try:
                async with session.get(url) as resp:
                    text = await resp.text()
                    elapsed = time.perf_counter() - start
                    result["time"] = elapsed
                    result["status"] = resp.status

                    if validate_status and resp.status != 200:
                        result["error"] = f"Unexpected status code: {resp.status}"
                        result["time"] = None
            except asyncio.TimeoutError:
                result["error"] = "Timeout"
            except aiohttp.ClientError as e:
                result["error"] = f"ClientError: {e}"
            except Exception as e:
                result["error"] = f"Unhandled error: {e}"

            results.append(result if return_details else result["time"])

            await asyncio.sleep(random.uniform(*delay_range))  # espera aleatoria

    return results


# NUEVAS FUNCIONES ULTRA AVANZADAS:

async def fetch_external_ip_info(ip: str):
    """
    Consulta extendida de información de IP pública con precisión simbiótica nivel Dios.
    
    Incluye: ubicación, organización, reputación, privacidad, validación, y señales de alerta.
    """
    def is_valid_ipv4(ip_str):
        return bool(re.fullmatch(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip_str))

    if not is_valid_ipv4(ip):
        return {"error": "IP inválida"}

    url = f"https://ipinfo.io/{ip}/json"
    signals = []
    result = {}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()

                    # Señales sospechosas o relevantes
                    org = data.get("org", "")
                    hostname = data.get("hostname", "")
                    loc = data.get("loc", "")
                    privacy_flags = []

                    if "amazon" in org.lower() or "google" in org.lower():
                        privacy_flags.append("Cloud Infra")
                    if "vpn" in hostname.lower() or "tor" in hostname.lower():
                        privacy_flags.append("Possible VPN/TOR Exit Node")
                    if re.match(r"^10\.|^172\.1[6-9]|^192\.168", ip):
                        privacy_flags.append("Private IP Detected")
                    
                    result = {
                        "ip": ip,
                        "hostname": hostname or None,
                        "city": data.get("city"),
                        "region": data.get("region"),
                        "country": data.get("country"),
                        "location": loc.split(",") if loc else None,
                        "org": org,
                        "postal": data.get("postal"),
                        "timezone": data.get("timezone"),
                        "as": org.split()[0] if org else None,
                        "suspicious_signals": privacy_flags,
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                    }

                    # Señales semánticas adicionales
                    if result.get("country") and result["country"].lower() not in ["mx", "us", "ca", "es"]:
                        signals.append("IP fuera de zona geográfica esperada")
                    if not hostname or hostname == ip:
                        signals.append("Hostname genérico o no resuelto")

                    result["enriched_signals"] = signals
                    return result

                else:
                    return {"error": f"HTTP {resp.status} al consultar IP info"}

    except asyncio.TimeoutError:
        return {"error": "Timeout en la solicitud"}
    except Exception as e:
        return {"error": f"Error inesperado: {str(e)}"}


async def fingerprint_advanced(url: str):
    headers = select_random_headers()

    # Delay humano random para evasión
    await asyncio.sleep(random.uniform(0.1, 0.5))

    try:
        html, raw_headers, cookies, final_url, status = await fetch_html(url, headers)

        hostname = urlparse(final_url).hostname or urlparse(url).hostname

        soup = BeautifulSoup(html, "html.parser")

        title = soup.title.string.strip() if soup.title else "No title"

        # Meta tags combinando "name" y "property"
        metas = {}
        for meta in soup.find_all("meta"):
            key = meta.get("name") or meta.get("property")
            if key and meta.get("content"):
                metas[key] = meta.get("content")

        # Scripts, links, favicons
        scripts = [script.get("src") for script in soup.find_all("script") if script.get("src")]
        links = [link.get("href") for link in soup.find_all("link") if link.get("href")]
        favicons = [link.get("href") for link in soup.find_all("link", rel=lambda x: x and 'icon' in x)]

        detected_frameworks, inline_script_samples = analyze_inline_scripts(soup)
        json_ld_data = parse_json_ld(soup)

        dns_ips = dns_lookup(hostname) if hostname else []
        reverse_dns_names = []
        for ip in dns_ips:
            name = reverse_dns(ip)
            if name:
                reverse_dns_names.append({"ip": ip, "reverse_dns": name})

        cdn_present = detectcdn(raw_headers)
        cookies_info = analyze_cookies(cookies)
        backend_tech = detect_technologies(html, raw_headers)
        security_headers = analyze_security_headers(raw_headers)
        ssl_info = analyze_ssl_certificate(hostname) if hostname else {}
        response_times = await measure_response_times(final_url, headers)

        # Whois info (pendiente)
        whois_info = whois_lookup(hostname) if hostname else {}

        # IP Info externa (geolocalización y reputación)
        ip_external_info = {}
        if dns_ips:
            ip_external_info = await fetch_external_ip_info(dns_ips[0])

        fingerprint = {
            "url_original": url,
            "url_final": final_url,
            "status_code": status,
            "title": title,
            "meta_tags": metas,
            "scripts": scripts,
            "links": links,
            "favicons": favicons,
            "detected_frameworks_and_trackers": list(set(detected_frameworks + backend_tech)),
            "inline_script_samples": inline_script_samples,
            "json_ld_structured_data": json_ld_data,
            "dns_ips": dns_ips,
            "reverse_dns_names": reverse_dns_names,
            "cdn_detected": cdn_present,
            "cookies": cookies_info,
            "backend_technologies": backend_tech,
            "security_headers": security_headers,
            "ssl_tls_info": ssl_info,
            "response_times_seconds": response_times,
            "whois_info": whois_info,
            "ip_external_info": ip_external_info,
            "user_agent_used": headers.get("User-Agent"),
            "raw_headers": raw_headers,
        }

        ip_info = []  # Preparado para futuras técnicas frontend/backend

        return {
            "fingerprint": fingerprint,
            "html": html[:2000],
            "ip_info": ip_info,
        }

    except Exception as e:
        return {
            "error": str(e),
            "fingerprint": {},
            "html": "",
            "ip_info": []
        }
