#!/usr/bin/env python3
"""Re-apply the OLSpanel patches the 3rd-party plugins depend on.

OLSpanel updates replace the panel's own Python files, which silently removes
the small patches that let the panel forward a working admin identity to the
plugins (and add the Reseller Portal to the customer area's Software menu).
This script re-applies them, idempotently, without touching any file that is
already patched.

It is safe to run from cron: it only writes when something is actually
missing, and it never copies plugin files or changes mtimes otherwise.

Usage:
    panel_repair.py            apply the patches, print what changed
    panel_repair.py --quiet    only log changes (cron)
    panel_repair.py --install-cron
                               install /etc/cron.d/olspanel-plugin-repair
"""

import glob
import os
import sys
import time

PROJECT_CANDIDATES = (
    "/usr/local/olspanel/mypanel",
    "/usr/local/lsws/Example/html/mypanel",
)
LOG_FILE = "/var/log/olspanel-plugin-repair.log"
CRON_FILE = "/etc/cron.d/olspanel-plugin-repair"


def project_dir():
    try:
        with open("/etc/olspanel/base_dir", encoding="utf-8") as f:
            path = f.read().strip()
        if path and os.path.isdir(path):
            return path
    except OSError:
        pass
    for path in PROJECT_CANDIDATES:
        if os.path.isdir(path):
            return path
    return ""


def log(message):
    line = "%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), message)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


def apply(project, rel, old, new, marker, quiet):
    """Replace old with new once, unless marker already proves it is patched."""
    path = os.path.join(project, rel)
    try:
        with open(path, encoding="utf-8") as f:
            src = f.read()
    except OSError:
        if not quiet:
            print("panel_repair: %s not found; skipping" % rel)
        return False
    if marker in src:
        return False
    if old not in src:
        msg = "WARNING could not patch %s (anchor changed); reinstall the plugin" % rel
        print("panel_repair: " + msg, file=sys.stderr)
        log(msg)
        return False
    tmp = path + ".panel-repair.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(src.replace(old, new, 1))
    os.replace(tmp, path)
    msg = "patched %s" % rel
    if not quiet:
        print("panel_repair: " + msg)
    log(msg)
    return True


def ensure_route(project, quiet):
    """Register the reseller API include, if that Django package is present."""
    if not os.path.isdir(os.path.join(project, "admin_api_resellers")):
        return False
    path = os.path.join(project, "user_management", "urls.py")
    try:
        with open(path, encoding="utf-8") as f:
            src = f.read()
    except OSError:
        return False
    if "admin_api_resellers.urls" in src:
        return False
    line = '    path("admin_api_resellers/", include("admin_api_resellers.urls")),\n'
    anchor = '    path("admin_api/", include("admin_api.urls")),\n'
    if anchor in src:
        src = src.replace(anchor, anchor + line, 1)
    else:
        # Fall back to the first include() line, then to urlpatterns itself.
        out = []
        inserted = False
        for raw in src.splitlines(True):
            out.append(raw)
            if not inserted and raw.strip().startswith("path(") and "include(" in raw:
                out.append(line)
                inserted = True
        if not inserted:
            out = []
            for raw in src.splitlines(True):
                out.append(raw)
                if not inserted and raw.strip().startswith("urlpatterns"):
                    out.append(line)
                    inserted = True
        src = "".join(out)
    if line not in src:
        return False
    tmp = path + ".panel-repair.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(src)
    os.replace(tmp, path)
    msg = "registered admin_api_resellers route"
    if not quiet:
        print("panel_repair: " + msg)
    log(msg)
    return True


# --- shared patches --------------------------------------------------------
# The admin panel authenticates into session_admin, so request.user is an
# AnonymousUser even for a signed-in administrator.
VIEWS_IDENTITY_OLD = """            # Prepare replacements only if needed
            if not request.user:
                username = request.admin_user.username if needs_username or needs_dbinfo else ''
                userid = str(request.admin_user.id) if needs_userid else ''
            else:
                username = request.user.username if needs_username or needs_dbinfo else ''
                userid = str(request.user.id) if needs_userid else ''
            encrypted_json = ''
            if needs_usertoken:
                if not request.user:
                    u_token = encode(get_auto_login_password(request.admin_user.username))
                else:
                    u_token = encode(get_auto_login_password(request.user.username))
"""

VIEWS_IDENTITY_NEW = """            # Prepare replacements only if needed. The admin panel authenticates
            # into a separate session (session_admin) and does not log the user
            # into the regular session, so request.user is an (unauthenticated)
            # AnonymousUser even for a signed-in administrator. Prefer the admin
            # identity when present; fall back to an authenticated regular user.
            effective_user = getattr(request, 'admin_user', None) or (
                request.user if request.user.is_authenticated else None
            )
            if effective_user:
                username = effective_user.username if needs_username or needs_dbinfo else ''
                userid = str(effective_user.id) if needs_userid else ''
                u_token = ''
            else:
                username = ''
                userid = ''
                u_token = ''
            encrypted_json = ''
            if needs_usertoken:
                u_token = encode(get_auto_login_password(effective_user.username)) if effective_user else ''
"""

VIEWS_OPTIONS_OLD = """def web_server(request, php_file):
    custom_cookies = get_custom_cookies(request, prefix="CUSTOMCOOK_")
"""

VIEWS_OPTIONS_NEW = """def web_server(request, php_file):
    # CORS preflight short-circuit.
    #
    # A browser sends an OPTIONS preflight before any non-simple cross-origin
    # request (for example a POST with Content-Type: application/json). This
    # route used to pass OPTIONS straight into the php-cgi subprocess, which
    # the panel proxy handles poorly: it both fails to answer the preflight with
    # the Access-Control-Allow-* headers the browser needs, and can wedge the
    # proxy's single accept loop. Answer the preflight here, before any plugin
    # work or subprocess is started, so it can never reach that code path.
    if request.method == "OPTIONS":
        response = HttpResponse(status=204)
        response["Allow"] = "GET, POST, OPTIONS"
        response["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        requested = request.META.get("HTTP_ACCESS_CONTROL_REQUEST_HEADERS", "")
        response["Access-Control-Allow-Headers"] = requested or "Content-Type, Accept, X-Requested-With"
        origin = request.META.get("HTTP_ORIGIN", "")
        if origin:
            response["Access-Control-Allow-Origin"] = origin
            response["Access-Control-Allow-Credentials"] = "true"
            response["Vary"] = "Origin"
        response["Access-Control-Max-Age"] = "600"
        return response

    custom_cookies = get_custom_cookies(request, prefix="CUSTOMCOOK_")
"""

DECORATORS_OPTIONS_OLD = """    def wrapper(request, *args, **kwargs):
        # Check if either regular user OR admin user is authenticated
        regular_user_authenticated = request.user.is_authenticated
"""

DECORATORS_OPTIONS_NEW = """    def wrapper(request, *args, **kwargs):
        # A CORS preflight (OPTIONS) never carries credentials: browsers send it
        # without cookies, so it can never satisfy a session check. It is a
        # metadata request, so let it reach the view, which answers it with the
        # Access-Control-Allow-* headers. Redirecting it to /login/ makes every
        # cross-origin fetch fail and, on this panel, can wedge the proxy.
        if request.method == "OPTIONS":
            return view_func(request, *args, **kwargs)

        # Check if either regular user OR admin user is authenticated
        regular_user_authenticated = request.user.is_authenticated
"""

# --- reseller-manager patches ---------------------------------------------
PLUGIN_SIGNATURE_OLD = "def get_software_plugins_list(softaculous):\n"
PLUGIN_SIGNATURE_NEW = "def get_software_plugins_list(softaculous, user=None):\n"

PLUGIN_PORTAL_OLD = """    # Conditionally add Softaculous
    if softaculous == 'yes':
        plugin_list.append({
            'name': 'Softaculous',
            'icon': '/media/icon/softaculous.png',
            'url': reverse('softaculous_view'),
            'sorder': 5,
            'target': '_blank',
        })

    # Sort the plugins by 'sorder'
    plugin_list.sort(key=lambda x: x['sorder'])

    return plugin_list
"""

PLUGIN_PORTAL_NEW = """    # Conditionally add Softaculous
    if softaculous == 'yes':
        plugin_list.append({
            'name': 'Softaculous',
            'icon': '/media/icon/softaculous.png',
            'url': reverse('softaculous_view'),
            'sorder': 5,
            'target': '_blank',
        })

    # Reseller Portal: shown only to an account that owns a package (a reseller).
    # The link goes straight to the plugin, which reads the panel-forwarded
    # identity and signs them in, so there is no second login.
    if user is not None and getattr(user, 'is_authenticated', False):
        try:
            from users.models import Package
            owns = Package.objects.filter(userid=user.id).exists()
        except Exception:
            owns = False
        if owns:
            plugin_list.append({
                'name': 'Reseller Portal',
                'icon': '/media/icon/reseller_portal.png',
                'url': '/3rdparty/reseller_portal/index.php',
                'sorder': 6,
                'target': '_self',
            })

    # Sort the plugins by 'sorder'
    plugin_list.sort(key=lambda x: x['sorder'])

    return plugin_list
"""


def harden_secrets(project, quiet):
    """Keep reversible password files readable by root only.

    OLSpanel writes etc/_<user> and etc/phpmyadmin_<user> with the process
    umask (usually 0644), which lets every member of the web-server group read
    a base64-encoded password. The panel reads these files as root, so 0600 is
    safe and closes that exposure for existing and future accounts.
    """
    changed = 0
    for pattern in ("_*", "phpmyadmin_*"):
        for path in glob.glob(os.path.join(project, "etc", pattern)):
            try:
                if not os.path.isfile(path) or os.path.islink(path):
                    continue
                if os.stat(path).st_mode & 0o077:
                    os.chmod(path, 0o600)
                    changed += 1
            except OSError:
                pass
    if changed:
        msg = "tightened permissions on %d password file(s)" % changed
        if not quiet:
            print("panel_repair: " + msg)
        log(msg)
    return changed > 0


def repair(project, quiet):
    changed = False

    changed |= harden_secrets(project, quiet)

    changed |= apply(
        project, "users/views.py", VIEWS_IDENTITY_OLD, VIEWS_IDENTITY_NEW,
        "effective_user = getattr(request, 'admin_user', None)", quiet,
    )
    changed |= apply(
        project, "users/views.py", VIEWS_OPTIONS_OLD, VIEWS_OPTIONS_NEW,
        "# CORS preflight short-circuit.", quiet,
    )
    changed |= apply(
        project, "users/decorators.py", DECORATORS_OPTIONS_OLD, DECORATORS_OPTIONS_NEW,
        "A CORS preflight (OPTIONS) never carries credentials", quiet,
    )

    reseller = os.path.join(project, "3rdparty", "reseller_manager")
    if os.path.isdir(reseller):
        changed |= ensure_route(project, quiet)
        changed |= apply(
            project, "users/views.py",
            "    software_plugin = get_software_plugins_list(softaculous)\n",
            "    software_plugin = get_software_plugins_list(softaculous, request.user)\n",
            "get_software_plugins_list(softaculous, request.user)", quiet,
        )
        changed |= apply(
            project, "users/context_processors.py",
            "        'software_plugin': get_software_plugins_list(softaculous),\n",
            "        'software_plugin': get_software_plugins_list(softaculous, getattr(request, 'user', None)),\n",
            "get_software_plugins_list(softaculous, getattr(request, 'user', None))", quiet,
        )
        changed |= apply(
            project, "users/plugin.py", PLUGIN_SIGNATURE_OLD, PLUGIN_SIGNATURE_NEW,
            "def get_software_plugins_list(softaculous, user=None):", quiet,
        )
        changed |= apply(
            project, "users/plugin.py", PLUGIN_PORTAL_OLD, PLUGIN_PORTAL_NEW,
            "# Reseller Portal: shown only to an account that owns a package", quiet,
        )

    if changed:
        log("repair complete (files changed); the panel reloads automatically")
    return changed


def install_cron():
    content = (
        "# Re-apply the OLSpanel patches the 3rd-party plugins need after a\n"
        "# panel update. The script only writes when a patch is missing.\n"
        "*/10 * * * * root /usr/local/bin/olspanel-plugin-repair --quiet\n"
    )
    with open(CRON_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(CRON_FILE, 0o644)
    print("panel_repair: installed %s" % CRON_FILE)


def main(argv):
    quiet = "--quiet" in argv
    project = ""
    if "--project" in argv:
        index = argv.index("--project")
        if index + 1 < len(argv):
            project = argv[index + 1]
    if not project:
        project = project_dir()
    if not project or not os.path.isdir(project):
        print("panel_repair: could not find the OLSpanel project directory", file=sys.stderr)
        return 1
    if "--install-cron" in argv:
        install_cron()
    repair(project, quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
