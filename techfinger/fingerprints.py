#!/usr/bin/env python3
"""
Built-in fingerprint database.

This module is DATA, not logic. To teach the tool a new technology you add a
Fingerprint entry here - no engine change required. Follows the same
"table you extend, not code you edit" pattern as PROVIDER_SUFFIXES in
takeover_check.py.

Each Fingerprint describes how to recognise one technology across several
techniques. A technique is (pattern, optional version-capturing group). The
engine (engine.py) applies each against the collected Evidence and records a
piece of evidence + confidence whenever one matches.

Version capture: if a pattern contains a group named 'ver' (?P<ver>...), the
captured text becomes a version candidate for that technique.

Author : Savaid Khan
License: MIT
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Confidence

# A loose but common version shape: 1, 1.2, 1.2.3, 1.2.3b4 ...
V = r"(?P<ver>\d+(?:\.\d+){0,3}(?:[a-z]\d*)?)"


@dataclass
class Fingerprint:
    name: str
    category: str
    # Each rule is a dict describing where and what to match. Supported keys:
    #   header: (header_name, regex)         match a response header value
    #   any_header: regex                    match against every header line
    #   cookie: regex                        match a Set-Cookie name
    #   body: regex                          match the HTML body
    #   meta_generator: regex                match the <meta name=generator> tag
    #   script: regex                        match a <script src=...> URL
    #   implies: [names]                     other techs implied when this hits
    rules: list[dict] = field(default_factory=list)
    implies: tuple[str, ...] = ()


def _c(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.I)


# --------------------------------------------------------------------------- #
# The database
# --------------------------------------------------------------------------- #

FINGERPRINTS: list[Fingerprint] = [

    # ---- Web servers ---------------------------------------------------- #
    Fingerprint("nginx", "web-server", [
        {"header": ("server", rf"nginx(?:/{V})?")},
    ]),
    Fingerprint("Apache", "web-server", [
        {"header": ("server", rf"apache(?:/{V})?")},
    ]),
    Fingerprint("Apache Tomcat", "web-server", [
        {"header": ("server", rf"(?:apache-)?coyote(?:/{V})?")},
        {"body": r"Apache Tomcat"},
    ]),
    Fingerprint("Microsoft IIS", "web-server", [
        {"header": ("server", rf"microsoft-iis(?:/{V})?")},
    ]),
    Fingerprint("LiteSpeed", "web-server", [
        {"header": ("server", rf"litespeed(?:/{V})?")},
    ]),
    Fingerprint("OpenResty", "web-server", [
        {"header": ("server", rf"openresty(?:/{V})?")},
    ]),
    Fingerprint("Caddy", "web-server", [
        {"header": ("server", r"caddy")},
    ]),
    Fingerprint("Gunicorn", "web-server", [
        {"header": ("server", rf"gunicorn(?:/{V})?")},
    ]),
    Fingerprint("Werkzeug", "web-server", [
        {"header": ("server", rf"werkzeug(?:/{V})?")},
    ]),
    Fingerprint("Jetty", "web-server", [
        {"header": ("server", rf"jetty(?:\(|/){V}?")},
    ]),

    # ---- Programming languages ----------------------------------------- #
    Fingerprint("PHP", "programming-language", [
        {"header": ("x-powered-by", rf"php(?:/{V})?")},
        {"cookie": r"^PHPSESSID$"},
        {"body": r"\.php(?:[?\"'/]|$)"},
    ]),
    Fingerprint("ASP.NET", "framework", [
        {"header": ("x-powered-by", r"asp\.net")},
        {"header": ("x-aspnet-version", rf"{V}")},
        {"cookie": r"^ASP\.NET_SessionId$"},
        {"cookie": r"^\.ASPXAUTH$"},
    ]),
    Fingerprint("Java", "programming-language", [
        {"cookie": r"^JSESSIONID$"},
    ]),
    Fingerprint("Python", "programming-language", [
        {"header": ("server", rf"python(?:/{V})?")},
    ]),
    Fingerprint("Ruby", "programming-language", [
        {"header": ("server", r"phusion passenger")},
    ]),
    Fingerprint("Node.js", "programming-language", [
        {"header": ("x-powered-by", r"express")},
    ]),

    # ---- Frameworks ----------------------------------------------------- #
    Fingerprint("Express", "framework", [
        {"header": ("x-powered-by", r"express")},
    ], implies=("Node.js",)),
    Fingerprint("Laravel", "framework", [
        {"cookie": r"^laravel_session$"},
        {"cookie": r"^XSRF-TOKEN$"},
    ], implies=("PHP",)),
    Fingerprint("Ruby on Rails", "framework", [
        {"header": ("x-powered-by", r"phusion passenger")},
        {"cookie": r"^_.*_session$"},
        {"header": ("x-runtime", r".+")},
    ], implies=("Ruby",)),
    Fingerprint("Django", "framework", [
        {"cookie": r"^(?:csrftoken|django_language)$"},
    ], implies=("Python",)),
    Fingerprint("Flask", "framework", [
        {"cookie": r"^session$", "header": ("server", r"werkzeug")},
    ], implies=("Python",)),
    Fingerprint("Spring", "framework", [
        {"body": r"org\.springframework"},
        {"header": ("x-application-context", r".+")},
    ], implies=("Java",)),

    # ---- CMS ------------------------------------------------------------ #
    Fingerprint("WordPress", "cms", [
        {"meta_generator": rf"wordpress(?:\s+{V})?"},
        {"body": r"/wp-content/"},
        {"body": r"/wp-includes/"},
        {"script": rf"/wp-includes/js/.*[?&]ver={V}"},
        {"header": ("link", r"/wp-json/")},
    ], implies=("PHP",)),
    Fingerprint("Drupal", "cms", [
        {"meta_generator": rf"drupal(?:\s+{V})?"},
        {"header": ("x-generator", rf"drupal(?:\s+{V})?")},
        {"header": ("x-drupal-cache", r".+")},
        {"body": r"/sites/(?:all|default)/"},
    ], implies=("PHP",)),
    Fingerprint("Joomla", "cms", [
        {"meta_generator": rf"joomla!?(?:\s+{V})?"},
        {"body": r"/media/jui/"},
        {"cookie": r"^[0-9a-f]{32}$"},
    ], implies=("PHP",)),
    Fingerprint("Ghost", "cms", [
        {"meta_generator": rf"ghost(?:\s+{V})?"},
    ]),
    Fingerprint("Magento", "cms", [
        {"cookie": r"^(?:frontend|X-Magento-Vary)$"},
        {"body": r"/skin/frontend/"},
    ], implies=("PHP",)),
    Fingerprint("Shopify", "cms", [
        {"any_header": r"x-shopify"},
        {"body": r"cdn\.shopify\.com"},
    ]),
    Fingerprint("Wix", "cms", [
        {"any_header": r"x-wix-"},
        {"body": r"static\.wixstatic\.com"},
    ]),

    # ---- JavaScript libraries ------------------------------------------ #
    Fingerprint("jQuery", "javascript-library", [
        {"script": rf"jquery[-.]{V}(?:\.min)?\.js"},
        {"body": rf"jquery[-.]{V}(?:\.min)?\.js"},
        {"body": rf"jquery v{V}"},
    ]),
    Fingerprint("React", "javascript-library", [
        {"script": rf"react(?:\.production|\.development)?[-.]?{V}?(?:\.min)?\.js"},
        {"body": r"data-reactroot"},
        {"body": r"__REACT_DEVTOOLS_GLOBAL_HOOK__"},
    ]),
    Fingerprint("Vue.js", "javascript-library", [
        {"script": rf"vue(?:@|[-.]){V}?(?:\.min)?\.js"},
        {"body": r"data-v-[0-9a-f]{8}"},
        {"body": r"__vue__"},
    ]),
    Fingerprint("Angular", "javascript-library", [
        {"body": r"ng-version=\"" + V + r"\""},
        {"script": rf"angular(?:[-.]){V}?(?:\.min)?\.js"},
        {"body": r"ng-app"},
    ]),
    Fingerprint("Next.js", "framework", [
        {"header": ("x-powered-by", r"next\.js")},
        {"body": r"/_next/static/"},
        {"script": r"/_next/"},
    ], implies=("React", "Node.js")),
    Fingerprint("Lodash", "javascript-library", [
        {"script": rf"lodash(?:[-.]){V}?(?:\.min)?\.js"},
    ]),
    Fingerprint("Moment.js", "javascript-library", [
        {"script": rf"moment(?:[-.]){V}?(?:\.min)?\.js"},
    ]),
    Fingerprint("D3.js", "javascript-library", [
        {"script": rf"d3(?:[-.v]){V}?(?:\.min)?\.js"},
    ]),

    # ---- CSS frameworks ------------------------------------------------- #
    Fingerprint("Bootstrap", "css-framework", [
        {"script": rf"bootstrap(?:[-.]){V}?(?:\.min)?\.(?:js|css)"},
        {"body": rf"bootstrap(?:[-.]){V}?(?:\.min)?\.css"},
        {"body": r"class=\"[^\"]*\b(?:col-(?:xs|sm|md|lg)-\d+|navbar-)"},
    ]),
    Fingerprint("Tailwind CSS", "css-framework", [
        # Require a real Tailwind asset or its build artefacts, not bare utility
        # class names - those (flex, px-2, ...) are far too common to trust.
        {"script": rf"tailwind(?:css)?(?:[-.@]{V})?(?:\.min)?\.(?:js|css)"},
        {"body": r"cdn\.tailwindcss\.com"},
        {"body": r"--tw-[a-z-]+\s*:"},          # Tailwind CSS custom properties
    ]),
    Fingerprint("Font Awesome", "css-framework", [
        {"body": rf"font-?awesome(?:[-.]){V}?"},
        {"body": r"class=\"[^\"]*\bfa[srlbd]?\s+fa-"},
    ]),

    # ---- CDN ------------------------------------------------------------ #
    Fingerprint("Cloudflare", "cdn", [
        {"any_header": r"cf-ray"},
        {"header": ("server", r"cloudflare")},
        {"cookie": r"^__cf"},
    ]),
    Fingerprint("Akamai", "cdn", [
        {"any_header": r"x-akamai"},
        {"header": ("server", r"akamaighost")},
    ]),
    Fingerprint("Fastly", "cdn", [
        {"any_header": r"x-served-by.*cache"},
        {"header": ("x-fastly-request-id", r".+")},
        {"header": ("via", r"varnish")},
    ]),
    Fingerprint("Amazon CloudFront", "cdn", [
        {"header": ("via", r"cloudfront")},
        {"any_header": r"x-amz-cf-"},
        {"header": ("x-cache", r"cloudfront")},
    ]),
    Fingerprint("Sucuri", "cdn", [
        {"header": ("server", r"sucuri")},
        {"any_header": r"x-sucuri"},
    ]),

    # ---- WAF ------------------------------------------------------------ #
    Fingerprint("Cloudflare WAF", "waf", [
        {"any_header": r"cf-ray"},
        {"body": r"attention required.*cloudflare"},
    ]),
    Fingerprint("Sucuri WAF", "waf", [
        {"any_header": r"x-sucuri-id"},
        {"header": ("server", r"sucuri/cloudproxy")},
    ]),
    Fingerprint("Imperva Incapsula", "waf", [
        {"any_header": r"x-iinfo"},
        {"cookie": r"^(?:incap_ses|visid_incap)"},
    ]),
    Fingerprint("F5 BIG-IP", "waf", [
        {"cookie": r"^(?:BIGipServer|TS[0-9a-f]+)"},
        {"any_header": r"x-waf-event"},
    ]),
    Fingerprint("AWS WAF", "waf", [
        {"any_header": r"x-amzn-waf"},
        {"cookie": r"^aws-waf-token$"},
    ]),

    # ---- Reverse proxy -------------------------------------------------- #
    Fingerprint("Varnish", "reverse-proxy", [
        {"header": ("via", rf"varnish(?:/{V})?")},
        {"any_header": r"x-varnish"},
    ]),
    Fingerprint("HAProxy", "reverse-proxy", [
        {"cookie": r"^SERVERID$"},
    ]),
    Fingerprint("Envoy", "reverse-proxy", [
        {"header": ("server", r"envoy")},
        {"any_header": r"x-envoy"},
    ]),

    # ---- API technologies ---------------------------------------------- #
    Fingerprint("GraphQL", "api", [
        {"body": r"\"__schema\""},
        {"body": r"graphql"},
    ]),
    Fingerprint("Swagger / OpenAPI", "api", [
        {"body": r"swagger-ui"},
        {"body": r"\"openapi\"\s*:"},
    ]),
    Fingerprint("WordPress REST API", "api", [
        {"header": ("link", r"/wp-json/")},
    ], implies=("WordPress",)),

    # ---- Analytics ------------------------------------------------------ #
    Fingerprint("Google Analytics", "analytics", [
        {"body": r"google-analytics\.com/(?:ga|analytics)\.js"},
        {"body": r"gtag\('config'"},
        {"script": r"googletagmanager\.com/gtag"},
    ]),
    Fingerprint("Google Tag Manager", "analytics", [
        {"body": r"googletagmanager\.com/gtm\.js"},
    ]),
    Fingerprint("Hotjar", "analytics", [
        {"body": r"static\.hotjar\.com"},
    ]),
    Fingerprint("Facebook Pixel", "analytics", [
        {"body": r"connect\.facebook\.net/.*/fbevents\.js"},
    ]),
    Fingerprint("Matomo", "analytics", [
        {"body": r"(?:matomo|piwik)\.js"},
    ]),

    # ---- Authentication ------------------------------------------------- #
    Fingerprint("OAuth 2.0", "authentication", [
        {"body": r"oauth2?/authorize"},
        {"body": r"response_type=code"},
    ]),
    Fingerprint("OpenID Connect", "authentication", [
        {"body": r"/\.well-known/openid-configuration"},
    ]),
    Fingerprint("Okta", "authentication", [
        {"body": r"\.okta\.com"},
        {"any_header": r"x-okta"},
    ]),
    Fingerprint("Auth0", "authentication", [
        {"body": r"\.auth0\.com"},
    ]),
    Fingerprint("SAML", "authentication", [
        {"body": r"urn:oasis:names:tc:SAML"},
        {"body": r"/saml/(?:login|sso|acs)"},
    ]),

    # ---- Build tools / package managers --------------------------------- #
    Fingerprint("webpack", "build-tool", [
        {"body": r"webpackJsonp"},
        {"script": r"/static/js/(?:main|runtime|chunk)"},
    ]),
    Fingerprint("Vite", "build-tool", [
        {"script": r"/@vite/"},
        {"body": r"/assets/index-[0-9a-f]+\.js"},
    ]),
    Fingerprint("Parcel", "build-tool", [
        {"body": r"parcelRequire"},
    ]),
    Fingerprint("Gatsby", "framework", [
        {"body": r"/page-data/"},
        {"body": r"___gatsby"},
    ], implies=("React",)),

    # ---- Operating system (weak hints, from Server banners) ------------- #
    Fingerprint("Ubuntu", "operating-system", [
        {"header": ("server", r"\(ubuntu\)")},
    ]),
    Fingerprint("Debian", "operating-system", [
        {"header": ("server", r"\(debian\)")},
    ]),
    Fingerprint("CentOS", "operating-system", [
        {"header": ("server", r"\(centos\)")},
    ]),
    Fingerprint("Red Hat", "operating-system", [
        {"header": ("server", r"\(red ?hat\)")},
    ]),
    Fingerprint("Windows Server", "operating-system", [
        {"header": ("server", r"microsoft-iis")},
    ]),
]


# --------------------------------------------------------------------------- #
# Security headers (checked separately - presence/absence, not a "technology")
# --------------------------------------------------------------------------- #

# name -> (header, why it matters). The engine reports which are present and
# which recommended ones are missing.
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces HTTPS; absence enables SSL-strip.",
    "Content-Security-Policy": "Mitigates XSS/data-injection.",
    "X-Frame-Options": "Mitigates clickjacking.",
    "X-Content-Type-Options": "Stops MIME-sniffing.",
    "Referrer-Policy": "Controls referrer leakage.",
    "Permissions-Policy": "Restricts powerful browser features.",
    "X-XSS-Protection": "Legacy XSS filter toggle.",
    "Cross-Origin-Opener-Policy": "Process isolation against XS-leaks.",
}

# Headers whose presence leaks information an attacker can use.
INFO_LEAK_HEADERS = {
    "Server": "Reveals server software/version.",
    "X-Powered-By": "Reveals backend technology/version.",
    "X-AspNet-Version": "Reveals exact ASP.NET version.",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version.",
    "X-Generator": "Reveals CMS/generator.",
}


# --------------------------------------------------------------------------- #
# CPE hints for the CVE lookup (Phase 3)
# --------------------------------------------------------------------------- #

# Maps our friendly technology name to the (vendor, product) used to build a
# CPE 2.3 string for NVD, plus the endoflife.date product slug when one exists.
# Only technologies with a meaningful CVE/EOL story are listed; the rest simply
# won't be enriched (and say so).
CPE_MAP: dict[str, dict] = {
    "nginx":            {"vendor": "f5",              "product": "nginx",     "eol": "nginx"},
    "Apache":           {"vendor": "apache",          "product": "http_server", "eol": "apache-http-server"},
    "Apache Tomcat":    {"vendor": "apache",          "product": "tomcat",    "eol": "tomcat"},
    "Microsoft IIS":    {"vendor": "microsoft",       "product": "internet_information_services"},
    "LiteSpeed":        {"vendor": "litespeedtech",   "product": "litespeed_web_server"},
    "OpenSSL":          {"vendor": "openssl",         "product": "openssl",   "eol": "openssl"},
    "PHP":              {"vendor": "php",             "product": "php",       "eol": "php"},
    "WordPress":        {"vendor": "wordpress",       "product": "wordpress", "eol": "wordpress"},
    "Drupal":           {"vendor": "drupal",          "product": "drupal",    "eol": "drupal"},
    "Joomla":           {"vendor": "joomla",          "product": "joomla\\!", "eol": "joomla"},
    "jQuery":           {"vendor": "jquery",          "product": "jquery",    "eol": "jquery"},
    "Bootstrap":        {"vendor": "getbootstrap",    "product": "bootstrap", "eol": "bootstrap"},
    "Angular":          {"vendor": "angular",         "product": "angular",   "eol": "angular"},
    "Vue.js":           {"vendor": "vuejs",           "product": "vue",       "eol": "vue"},
    "Django":           {"vendor": "djangoproject",   "product": "django",    "eol": "django"},
    "Laravel":          {"vendor": "laravel",         "product": "laravel",   "eol": "laravel"},
    "ASP.NET":          {"vendor": "microsoft",       "product": "asp.net"},
    "Express":          {"vendor": "expressjs",       "product": "express"},
    "Node.js":          {"vendor": "nodejs",          "product": "node.js",   "eol": "nodejs"},
    "Ruby on Rails":    {"vendor": "rubyonrails",     "product": "rails",     "eol": "rails"},
    "Spring":           {"vendor": "vmware",          "product": "spring_framework", "eol": "spring-framework"},
    "Magento":          {"vendor": "magento",         "product": "magento",   "eol": "magento"},
    "Ghost":            {"vendor": "ghost",           "product": "ghost"},
    "Varnish":          {"vendor": "varnish-cache",   "product": "varnish_cache"},
    "Next.js":          {"vendor": "vercel",          "product": "next.js",   "eol": "nextjs"},
    "Lodash":           {"vendor": "lodash",          "product": "lodash"},
    "Moment.js":        {"vendor": "momentjs",        "product": "moment"},
    "Python":           {"vendor": "python",          "product": "python",    "eol": "python"},
}
