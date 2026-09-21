"""FIPS-mode GSSAPI/SPNEGO HTTPS authentication test for python3-requests-gssapi.

This is the openQA-agnostic part of tests/security/oqa_agnostic/fips_requests_gssapi.pm.
The fixture creates a local Kerberos realm restricted to the FIPS-approved AES256
enctypes and an Apache HTTPS virtual host that protects /protected with
mod_auth_gssapi. The tests then exercise python3-requests-gssapi, the package
whose FIPS behaviour is under test (bsc#1266006, PED-16727).

The test targets SLE 15-SP7 and its Python 3.6, so only Python 3.6 compatible
APIs are used (no capture_output=, no text=, no f-strings).
"""

import glob
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
import requests
from requests_gssapi import HTTPSPNEGOAuth

BASE_DIR = Path(__file__).parent
REALM = "EXAMPLE.COM"
DB_PASS = "openqa_db_pass"
TEST_USER = "testuser"
TEST_KEYTAB = Path("/root/testuser.keytab")
APACHE_KEYTAB = Path("/etc/apache2/http.keytab")
CCACHE_PATH = Path("/tmp/gssapi_fips_ccache")
WEAK_CCACHE_PATH = Path("/tmp/gssapi_fips_weak_ccache")
KDC_CONF = Path("/var/lib/kerberos/krb5kdc/kdc.conf")
KRB5_CONF = Path("/etc/krb5.conf")
# a2enmod and the SSL server flag both live in /etc/sysconfig/apache2, so restoring
# that one file undoes every Apache change this test makes outside of vhosts.d
SYSCONFIG_APACHE = Path("/etc/sysconfig/apache2")
# files that are replaced wholesale and put back by _teardown()
BACKED_UP = (KRB5_CONF, KDC_CONF, SYSCONFIG_APACHE)
HOSTS = Path("/etc/hosts")
HOSTS_MARKER = "# openqa-gssapi-fips"
VHOST_CONF = Path("/etc/apache2/vhosts.d/gssapi-fips.conf")
APACHE_CRT = Path("/etc/apache2/ssl.crt/gssapi-fips.crt")
APACHE_KEY = Path("/etc/apache2/ssl.key/gssapi-fips.key")
WEB_ROOT_FILE = Path("/srv/www/htdocs/protected")

APPROVED_ENCTYPES = {"aes256-cts-hmac-sha1-96", "aes256-cts-hmac-sha384-192"}
WEAK_ENCTYPE = "arcfour-hmac"
HTTP_TIMEOUT = 15


def run(cmd, check=True, env=None):
    """Run a command and return the completed process with combined output."""
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        universal_newlines=True, env=env,
    )
    if check and proc.returncode != 0:
        raise AssertionError(
            "Command %s failed with %d:\n%s" % (cmd, proc.returncode, proc.stdout)
        )
    return proc


def _fqdn():
    fqdn = run(["hostname", "-f"]).stdout.strip().lower()
    assert fqdn, "hostname -f returned an empty name"
    try:
        socket.getaddrinfo(fqdn, None)
    except socket.gaierror:
        with open(str(HOSTS), "a") as hosts:
            hosts.write("127.0.0.1 %s %s\n" % (fqdn, HOSTS_MARKER))
    return fqdn


def _enable_apache_ssl_flag():
    sysconfig = SYSCONFIG_APACHE
    content = sysconfig.read_text()
    match = re.search(r'^APACHE_SERVER_FLAGS="([^"]*)"', content, re.MULTILINE)
    flags = match.group(1) if match else ""
    if "SSL" not in flags.split():
        content = re.sub(
            r"^APACHE_SERVER_FLAGS=.*",
            'APACHE_SERVER_FLAGS="%s"' % (flags + " SSL").strip(),
            content, count=1, flags=re.MULTILINE,
        )
        sysconfig.write_text(content)


def _wait_for_port(port, timeout=30):
    proc = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        proc = run(["ss", "-tln"], check=False)
        if re.search(r":%d\s" % port, proc.stdout):
            return
        time.sleep(0.5)
    raise AssertionError("Nothing is listening on port %d:\n%s" % (port, proc.stdout))


def _klist_enctypes(output):
    enctypes = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Etype (skey, tkt):"):
            enctypes.extend(e.strip() for e in line.split(":", 1)[1].split(","))
    return enctypes


def _backup_path(path):
    return Path(str(path) + ".openqa-bak")


def _kdb_files():
    """The KDC database and its stash, whatever realm they were created for."""
    return (glob.glob("/var/lib/kerberos/krb5kdc/principal*")
            + glob.glob("/var/lib/kerberos/krb5kdc/.k5.*"))


def _teardown():
    run(["systemctl", "stop", "apache2"], check=False)
    run(["systemctl", "stop", "krb5kdc"], check=False)
    leftovers = [VHOST_CONF, APACHE_CRT, APACHE_KEY, TEST_KEYTAB, APACHE_KEYTAB,
                 WEB_ROOT_FILE, CCACHE_PATH, WEAK_CCACHE_PATH]
    for path in leftovers + _kdb_files():
        try:
            os.remove(str(path))
        except OSError:
            pass
    for original in BACKED_UP:
        backup = _backup_path(original)
        if backup.exists():
            shutil.move(str(backup), str(original))
    hosts = HOSTS.read_text()
    if HOSTS_MARKER in hosts:
        HOSTS.write_text("".join(
            line for line in hosts.splitlines(True) if HOSTS_MARKER not in line
        ))


@pytest.fixture(scope="session")
def gssapi_env():
    """Set up a local FIPS-mode Kerberos realm and an Apache HTTPS host that
    protects /protected with mod_auth_gssapi. Yields a dict with the host FQDN
    and the HTTP service principal."""
    fqdn = _fqdn()
    http_principal = "HTTP/%s" % fqdn

    fips_enabled = Path("/proc/sys/crypto/fips_enabled").read_text().strip()
    assert fips_enabled == "1", (
        "FIPS mode is not enabled (/proc/sys/crypto/fips_enabled=%s)" % fips_enabled
    )

    run(["systemctl", "stop", "apache2"], check=False)
    run(["systemctl", "stop", "krb5kdc"], check=False)
    run(["systemctl", "stop", "firewalld"], check=False)

    # always start from a clean KDC database
    for path in _kdb_files():
        os.remove(path)

    try:
        for original in BACKED_UP:
            shutil.copy(str(original), str(_backup_path(original)))
        KRB5_CONF.write_text((BASE_DIR / "krb5.conf").read_text().replace("@FQDN@", fqdn))
        shutil.copy(str(BASE_DIR / "kdc.conf"), str(KDC_CONF))

        run(["kdb5_util", "create", "-r", REALM, "-s", "-P", DB_PASS])
        run(["kadmin.local", "-q", "addprinc -randkey %s" % TEST_USER])
        run(["kadmin.local", "-q", "addprinc -randkey %s" % http_principal])
        run(["kadmin.local", "-q", "ktadd -k %s %s" % (TEST_KEYTAB, TEST_USER)])
        run(["kadmin.local", "-q", "ktadd -k %s %s" % (APACHE_KEYTAB, http_principal)])
        os.chmod(str(APACHE_KEYTAB), 0o640)
        shutil.chown(str(APACHE_KEYTAB), "wwwrun", "www")

        run(["systemctl", "start", "krb5kdc"])
        assert run(["systemctl", "is-active", "krb5kdc"]).stdout.strip() == "active"

        os.environ["KRB5CCNAME"] = "FILE:" + str(CCACHE_PATH)
        run(["kinit", "-kt", str(TEST_KEYTAB), TEST_USER])

        # self-signed certificate and virtual host for the HTTPS endpoint
        run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(APACHE_KEY), "-out", str(APACHE_CRT),
            "-days", "1", "-subj", "/CN=%s" % fqdn,
            "-addext", "subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1" % fqdn,
        ])
        VHOST_CONF.write_text((BASE_DIR / "apache-gssapi.conf").read_text().replace("@FQDN@", fqdn))
        run(["a2enmod", "ssl", "auth_gssapi"])
        _enable_apache_ssl_flag()
        WEB_ROOT_FILE.write_text("GSSAPI authentication succeeded\n")

        run(["systemctl", "restart", "apache2"])
        _wait_for_port(443)

        yield {"fqdn": fqdn, "http_principal": http_principal}
    finally:
        _teardown()


def _protected_url(config):
    return "https://%s/protected" % config["fqdn"]


def test_unauthenticated_request_returns_401(gssapi_env):
    """An anonymous request must be rejected and Apache must offer Negotiate."""
    response = requests.get(_protected_url(gssapi_env), verify=False, timeout=HTTP_TIMEOUT)
    assert response.status_code == 401, response.text
    assert "negotiate" in response.headers.get("WWW-Authenticate", "").lower()


def test_https_spnego_auth_returns_200(gssapi_env):
    """Regression check for bsc#1266006: HTTPSPNEGOAuth must authenticate
    successfully over HTTPS instead of failing with a 401."""
    response = requests.get(
        _protected_url(gssapi_env), auth=HTTPSPNEGOAuth(),
        verify=False, timeout=HTTP_TIMEOUT,
    )
    assert response.status_code == 200, (
        "requests_gssapi authentication failed with %d:\n%s"
        % (response.status_code, response.text)
    )


def test_fips_approved_enctypes_used(gssapi_env):
    """The TGT and the HTTP service ticket obtained by the requests_gssapi
    exchange must only use the FIPS-approved AES256 enctypes."""
    run(["kdestroy"], check=False)
    run(["kinit", "-kt", str(TEST_KEYTAB), TEST_USER])
    response = requests.get(
        _protected_url(gssapi_env), auth=HTTPSPNEGOAuth(),
        verify=False, timeout=HTTP_TIMEOUT,
    )
    assert response.status_code == 200, response.text

    output = run(["klist", "-e"]).stdout
    assert "krbtgt/%s@%s" % (REALM, REALM) in output, output
    assert gssapi_env["http_principal"] in output, output

    enctypes = _klist_enctypes(output)
    assert enctypes, "klist -e did not report any enctypes:\n%s" % output
    unexpected = sorted(set(enctypes) - APPROVED_ENCTYPES)
    assert not unexpected, (
        "Non-approved enctypes found in the credential cache: %s\n%s"
        % (", ".join(unexpected), output)
    )
    assert any(enctype.startswith("aes256-") for enctype in enctypes)


def test_apache_keytab_uses_approved_enctypes(gssapi_env):
    """The HTTP service keytab used by Apache must only hold AES256 keys."""
    output = run(["klist", "-kte", str(APACHE_KEYTAB)]).stdout
    assert gssapi_env["http_principal"] in output, output
    enctypes = re.findall(r"\(([^()]+)\)", output)
    assert enctypes, "klist -kte did not report any enctypes:\n%s" % output
    unexpected = sorted(set(enctypes) - APPROVED_ENCTYPES)
    assert not unexpected, (
        "Non-approved enctypes found in %s: %s\n%s"
        % (APACHE_KEYTAB, ", ".join(unexpected), output)
    )


def test_weak_enctype_key_creation_rejected(gssapi_env):
    """FIPS mode must refuse to create a key with a non-approved enctype.

    Unlike the kvno check below, this does not depend on the enctypes we
    restricted the realm to: 'addprinc -e' asks the KDC for that enctype
    explicitly, so it is the crypto backend in FIPS mode that has to say no.
    A silent fallback to an AES key would be exactly the kind of downgrade
    bsc#1266006 is about, so an AES key here is a failure too."""
    principal = "weakprinc"
    result = run(
        ["kadmin.local", "-q",
         "addprinc -randkey -e %s:normal %s" % (WEAK_ENCTYPE, principal)],
        check=False,
    )
    listing = run(["kadmin.local", "-q", "getprinc %s" % principal], check=False).stdout
    created = "Principal: %s@%s" % (principal, REALM) in listing
    try:
        assert not created, (
            "FIPS mode created %s with a fallback key instead of refusing the "
            "non-approved enctype %s:\n%s" % (principal, WEAK_ENCTYPE, listing)
        )
        assert result.returncode != 0 or "error" in result.stdout.lower(), (
            "kadmin.local accepted the non-approved enctype %s without an error:\n%s"
            % (WEAK_ENCTYPE, result.stdout)
        )
    finally:
        if created:
            run(["kadmin.local", "-q", "delprinc -force %s" % principal], check=False)


def test_weak_enctype_rejected(gssapi_env):
    """FIPS mode must reject a non-approved enctype cleanly instead of silently
    falling back to it."""
    run(["kdestroy"], check=False)
    run(["kinit", "-kt", str(TEST_KEYTAB), TEST_USER])
    if WEAK_CCACHE_PATH.exists():
        os.remove(str(WEAK_CCACHE_PATH))
    shutil.copy(str(CCACHE_PATH), str(WEAK_CCACHE_PATH))

    env = os.environ.copy()
    env["KRB5CCNAME"] = "FILE:" + str(WEAK_CCACHE_PATH)
    result = run(
        ["kvno", "-e", WEAK_ENCTYPE, gssapi_env["http_principal"]],
        check=False, env=env,
    )
    assert result.returncode != 0, (
        "Requesting the non-approved enctype %s unexpectedly succeeded:\n%s"
        % (WEAK_ENCTYPE, result.stdout)
    )

    output = run(["klist", "-e"], check=False, env=env).stdout
    assert WEAK_ENCTYPE not in output, (
        "A ticket with the non-approved enctype %s ended up in the cache:\n%s"
        % (WEAK_ENCTYPE, output)
    )
