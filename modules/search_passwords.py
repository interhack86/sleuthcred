#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced search for passwords and credentials in SMB files using categorized regex patterns
with context, statistics and integration with a lightweight enricher (nxc_credential_detector).
Fixed syntax error (mismatched bracket/parenthesis) and added PRINT_FALLBACK behavior.
"""
import re
import time
import json
import sys
from os.path import join, abspath
from nxc.protocols.smb.remotefile import RemoteFile
from nxc.paths import NXC_PATH
from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError
from impacket.nmb import NetBIOSTimeout
from nxc.helpers.misc import CATEGORY

# Try to import the enricher. If not present, the module will continue to work using
# the original lightweight match structure.
try:
    sys.path.insert(0, "/root/.nxc/modules")
    from detector.nxc_credential_detector import enrich_match
    #enrich_match = None
except Exception:
    enrich_match = None

# =============================================================================
# CONFIGURATION - Modify this variable as needed
# =============================================================================
CUSTOM_FOLDER = None  # Set to "Telecomunicaciones" or any folder to force it
# =============================================================================


class SMBCredentialSearcher:
    def __init__(self, smb, logger, target_share, target_folder, max_file_size, max_depth,
                 pattern_types=None, context_lines=2, output_folder=None, stats_flag=True, debug_flag=False,
                 print_fallback=True):
        self.smb = smb
        self.logger = logger
        self.target_share = target_share
        self.target_folder = target_folder
        self.max_file_size = max_file_size
        self.max_depth = max_depth
        self.context_lines = context_lines
        self.output_folder = output_folder
        self.stats_flag = stats_flag
        self.debug_flag = debug_flag
        self.print_fallback = bool(print_fallback)
        self.max_connection_attempts = 5

        # Statistics tracking following spider_plus pattern
        self.stats = {
            "shares": [],
            "shares_readable": [],
            "num_shares_filtered": 0,
            "num_files": 0,
            "num_files_processed": 0,
            "num_files_filtered": 0,
            "num_matches_found": 0,
            "matches_by_category": {},
            "files_with_matches": 0
        }

        # Results storage
        self.results = {}

        # Network error tracking
        self.consecutive_network_errors = 0
        self.max_consecutive_errors = 5

        # Categorized regex patterns
        self.pattern_categories = {
            'hashes': {
                'md5_crypt': r'\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}',
                'apr1_crypt': r'\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}',
                'bcrypt': r'\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]{53}',
                'sha512_crypt': r'\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}',
                'phpass': r'\$P\$[a-zA-Z0-9_/\.]{31}',
                'wordpress': r'\$H\$[a-zA-Z0-9_/\.]{31}',
                'drupal': r'\$S\$[a-zA-Z0-9_/\.]{52}',
                'sha_hash': r'\{SHA\}[0-9a-zA-Z/_=]{20,}',
                'ntlm_hash': r'(?:^|[^a-fA-F0-9])[a-fA-F0-9]{32}:(?:[a-fA-F0-9]{32}|[a-zA-Z0-9_]{16,32})(?:[^a-fA-F0-9]|$)',
                'md5_hash': r'(?:^|[^a-fA-F0-9])[a-fA-F0-9]{32}(?:[^a-fA-F0-9]|$)',
                'sha1_hash': r'(?:^|[^a-fA-F0-9])[a-fA-F0-9]{40}(?:[^a-fA-F0-9]|$)',
                'sha256_hash': r'(?:^|[^a-fA-F0-9])[a-fA-F0-9]{64}(?:[^a-fA-F0-9]|$)',
                'sha512_hash': r'(?:^|[^a-fA-F0-9])[a-fA-F0-9]{128}(?:[^a-fA-F0]|$)'
            },
            'aws': {
                'access_key': r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
                'mws_key': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
            },
            'google': {
                'api_key': r'AIza[0-9A-Za-z_\-]{35}',
                'oauth_client': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
                'oauth_token': r'ya29\.[0-9A-Za-z_\-]+',
                'service_account': r'"type"\s*:\s*"service_account"'
            },
            'tokens': {
                'basic_auth': r'basic\s+[a-zA-Z0-9_:\.=\-]+',
                'bearer_token': r'bearer\s+[a-zA-Z0-9_\.=\-]+',
                'jwt_token': r'eyJ[a-zA-Z0-9+/]+\.eyJ[a-zA-Z0-9+/]+\.[a-zA-Z0-9+/\-_]*',
                'base64_data': r'(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+/]+=*'
            },
            'services': {
                'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
                'slack_webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{10}/B[a-zA-Z0-9_]{10}/[a-zA-Z0-9_]{24}',
                'stripe_key': r'sk_live_[0-9a-z]{32}',
                'stripe_public': r'pk_live_[0-9a-z]{24}',
                'square_token': r'sqOatp-[0-9A-Za-z_\-]{22}',
                'square_secret': r'sq0csp-[0-9A-Za-z_\-]{43}',
                'twilio_key': r'SK[0-9a-fA-F]{32}',
                'facebook_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
                'heroku_key': r'[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
                'mailchimp_key': r'[0-9a-f]{32}-us[0-9]{1,2}',
                'cloudinary_url': r'cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+'
            },
            'generic': {
                'url_credentials': r'[a-zA-Z][a-zA-Z0-9+.-]*://[a-zA-Z0-9]+:[a-zA-Z0-9!@#$%^&*()_+=\-\[\]{}|;:,.<>?]+@[a-zA-Z0-9.-]+',
                'email': r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}',
                'ip_address': r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
                'private_key': r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                'api_key_generic': r'(?:api[_-]?key|apikey|key)["\'\s]*[:=]["\'\s]*[a-zA-Z0-9_\-]{16,64}',
                'password_field': r'(?:password|passwd|pwd)["\'\s]*[:=]["\'\s]*[^\s"\']{4,64}'
            }
        }

        # Compile all patterns
        self.compiled_patterns = {}
        for category, patterns in self.pattern_categories.items():
            self.compiled_patterns[category] = {}
            for name, pattern in patterns.items():
                try:
                    self.compiled_patterns[category][name] = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    self.logger.debug(f"Invalid regex pattern {name}: {e}")

        # Selected pattern types
        self.enabled_patterns = pattern_types or list(self.pattern_categories.keys())

        self.file_extensions = [".ini", ".txt", ".xml", ".bat", ".config", ".conf", ".log", ".sql", ".sh", ".ps1", ".php", ".csv", ".yml", '.env', '.json']

        # Skip patterns / keywords
        self.skip_file_patterns = [
            'catalago', 'catalog', 'balance', 'forecast', 'backup', 'temp', 'tmp',
            'cache', 'index', 'log', 'dump', 'export', 'import', 'data'
        ]

        self.credential_filename_keywords = [
            'password', 'passwords', 'passwd', 'pwd', 'pass',
            'clave', 'claves', 'contraseña', 'contraseñas', 'credencial', 'credenciales',
            'login', 'logins', 'user', 'users', 'account', 'accounts', 'cuenta', 'cuentas',
            'secret', 'secrets', 'secreto', 'secretos', 'key', 'keys', 'llave', 'llaves',
            'auth', 'authentication', 'autenticacion', 'token', 'tokens', 'api',
            'config', 'configuration', 'configuracion', 'settings', 'ajustes',
            'database', 'db', 'base_datos', 'basedatos', 'mysql', 'postgres', 'sql',
            'ftp', 'sftp', 'ssh', 'vpn', 'wifi', 'email', 'mail', 'smtp', 'pop3', 'imap'
        ]

        self.system_files_to_ignore = [
            'thumbs.db', 'desktop.ini', '.ds_store', 'folder.jpg', 'albumartsmall.jpg',
            'autorun.inf', 'recycler', 'pagefile.sys', 'hiberfil.sys', 'swapfile.sys',
            'ntuser.dat', 'ntuser.dat.log', 'ntuser.pol', 'usrclass.dat',
            'bootmgr', 'bootmgfw.efi', 'bcd', 'boot.ini', 'config.sys', 'autoexec.bat',
            'msdos.sys', 'io.sys', 'command.com', 'ntldr', 'ntdetect.com',
            '.git', '.svn', '.hg', 'cvs', '.gitignore', '.gitkeep', '.htaccess',
            'license.txt', 'readme.txt', 'changelog.txt', 'copying', 'install.txt',
            'version.txt', 'history.txt', 'authors.txt', 'contributors.txt'
        ]

        self.ignore_extensions = [
            '.exe', '.dll', '.sys', '.bin', '.obj', '.lib', '.pdb', '.msi', '.cab',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.tiff', '.webp',
            '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.wav', '.m4a',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso', '.img',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods'
        ]

    def _display_match(self, file_path, line_num, category=None, pattern_name=None, match_text=None, context=None, enriched=None):
        """Unified display of a match: supports enriched dict or simple match_info."""
        try:
            ctx = context or []
            if enriched is not None:
                fv = enriched.get("final_verdict", "uncertain")
                score = enriched.get("final_score", 0.0)
                token = enriched.get("token", match_text or enriched.get("match", ""))
                display_category = category or enriched.get("category", "content")
                self.logger.highlight(f"[{display_category.upper()}] {file_path} (Line {line_num}): {token} -> {fv} (score={score})")
                #if self.context_lines > 0 and ctx:
                #    for ctx_line in ctx:
                #        if ctx_line.strip():
                #            self.logger.display(f"    Context: {ctx_line.strip()}")
            else:
                display_category = category or (pattern_name.split('.')[0] if pattern_name else "content")
                pname = pattern_name or "match"
                self.logger.highlight(f"[{display_category.upper()}] {file_path} (Line {line_num}): {match_text} ({pname})")
                if self.context_lines > 0 and ctx:
                    for ctx_line in ctx:
                        if ctx_line.strip():
                            self.logger.display(f"    Context: {ctx_line.strip()}")
        except Exception:
            try:
                self.logger.highlight(f"[MATCH] {file_path} (Line {line_num}): {match_text or '<unknown>'}")
            except Exception:
                pass

    def reconnect(self):
        """Reconnect with progressive backoff and limits."""
        current_time = time.time()
        if hasattr(self, '_last_reconnect_time'):
            if current_time - self._last_reconnect_time < 5:
                self.logger.debug("Skipping reconnection - too soon since last attempt")
                return False
        self._last_reconnect_time = current_time

        if not hasattr(self, '_total_reconnects'):
            self._total_reconnects = 0
        self._total_reconnects += 1
        if self._total_reconnects > 20:
            self.logger.debug("Too many reconnection attempts in this session")
            return False

        for i in range(1, self.max_connection_attempts + 1):
            self.logger.debug(f"Reconnection attempt #{i}/{self.max_connection_attempts} to server.")
            try:
                try:
                    if hasattr(self.smb, 'conn') and self.smb.conn:
                        self.smb.conn.close()
                except Exception:
                    pass

                time.sleep(i)
                self.smb.create_conn_obj()
                self.smb.login()
                self.logger.debug("Reconnection successful")
                return True
            except Exception as e:
                error_str = str(e)
                self.logger.debug(f"Reconnection attempt {i} failed: {error_str[:50]}...")
                if any(error in error_str.lower() for error in ['authentication', 'login', 'credentials', 'access_denied']):
                    self.logger.debug("Authentication error - stopping reconnection attempts")
                    return False
                if i < self.max_connection_attempts:
                    time.sleep(i * 2)
                continue
        self.logger.debug("All reconnection attempts failed")
        return False

    def list_path(self, share, subfolder):
        """List path entries on a share with error handling."""
        if subfolder in ["", "."]:
            path_pattern = "*"
        elif subfolder.startswith("*/"):
            path_pattern = subfolder[2:] + "/*"
        else:
            path_pattern = subfolder.replace("/*/", "/") + "/*"

        try:
            return self.smb.conn.listPath(share, path_pattern)
        except SessionError as e:
            error_str = str(e)
            if "STATUS_ACCESS_DENIED" in error_str:
                self.logger.debug(f'Access denied listing folder "{subfolder}" on share "{share}"')
                return []
            elif "STATUS_OBJECT_PATH_NOT_FOUND" in error_str:
                self.logger.debug(f'Folder "{subfolder}" does not exist on share "{share}"')
                return []
            elif "STATUS_NO_SUCH_FILE" in error_str:
                self.logger.debug(f'No such file/folder "{subfolder}" on share "{share}"')
                return []
            else:
                self.logger.debug(f'Session error listing folder "{subfolder}" on share "{share}": {error_str}')
                if hasattr(self, '_reconnect_attempts'):
                    self._reconnect_attempts += 1
                else:
                    self._reconnect_attempts = 1
                if self._reconnect_attempts <= 1 and self.reconnect():
                    self._reconnect_attempts = 0
                    return self.list_path(share, subfolder)
                self._reconnect_attempts = 0
                return []
        except NetBIOSTimeout as e:
            self.logger.debug(f'Timeout listing folder "{subfolder}" on share "{share}": {e!s}')
            return []
        except Exception as e:
            self.logger.debug(f'Unexpected error listing folder "{subfolder}" on share "{share}": {e!s}')
            return []

    def get_remote_file(self, share, path):
        """Return RemoteFile or None with reconnect attempts."""
        try:
            return RemoteFile(self.smb.conn, path, share, access=FILE_READ_DATA)
        except SessionError as e:
            self.logger.debug(f'Failed to access remote file "{path}" on share "{share}": {e!s}')
            if self.reconnect():
                return self.get_remote_file(share, path)
        except Exception as e:
            self.logger.debug(f'Unexpected error accessing remote file "{path}" on share "{share}": {e!s}')
        return None

    def search_patterns_in_content(self, content, file_path):
        """Search for credential patterns in file content with improved detection and context."""
        findings = 0
        lines = content.splitlines()
        file_matches = []

        for line_num, line in enumerate(lines[:500], 1):
            line = line.strip()
            if len(line) < 4:
                continue

            for category in self.enabled_patterns:
                if category not in self.compiled_patterns:
                    continue
                for pattern_name, compiled_pattern in self.compiled_patterns[category].items():
                    try:
                        matches = compiled_pattern.finditer(line)
                        for match in matches:
                            match_text = match.group()
                            if not (4 <= len(match_text) <= 500):
                                continue

                            context = self.get_context(lines, line_num - 1, self.context_lines)

                            if enrich_match is not None:
                                try:
                                    if "/" in file_path:
                                        share_name, _ = file_path.split("/", 1)
                                    else:
                                        share_name = ""
                                    enriched = enrich_match(
                                        category=category,
                                        pattern_name=pattern_name,
                                        token=match_text,
                                        line=line,
                                        token_start=match.start(),
                                        token_end=match.end(),
                                        share=share_name,
                                        file_path=file_path,
                                        line_num=line_num,
                                        context_lines=context
                                    )
                                    file_matches.append(enriched)
                                    if category not in self.stats["matches_by_category"]:
                                        self.stats["matches_by_category"][category] = 0
                                    self.stats["matches_by_category"][category] += 1
                                    self.stats["num_matches_found"] += 1

                                    fv = enriched.get("final_verdict", "uncertain")
                                    score = enriched.get("final_score", 0.0)
                                    if fv in ("likely_credential", "likely_hash", "alert_hash") or score >= 0.8:
                                        try:
                                            self._display_match(file_path, line_num, category=category, pattern_name=pattern_name, match_text=match_text, context=context, enriched=enriched)
                                        except Exception:
                                            pass
                                    else:
                                        if self.debug_flag:
                                            try:
                                                self._display_match(file_path, line_num, category=category, pattern_name=pattern_name, match_text=match_text, context=context, enriched=enriched)
                                            except Exception:
                                                pass
                                except Exception as e:
                                    self.logger.debug(f"Enricher failed for pattern {pattern_name} in {file_path}: {e}")
                                    match_info = {
                                        'type': f"{category}.{pattern_name}",
                                        'match': match_text,
                                        'line': line_num,
                                        'context': context
                                    }
                                    file_matches.append(match_info)
                                    if category not in self.stats["matches_by_category"]:
                                        self.stats["matches_by_category"][category] = 0
                                    self.stats["matches_by_category"][category] += 1
                                    self.stats["num_matches_found"] += 1

                                    if self.debug_flag or self.print_fallback:
                                        try:
                                            self._display_match(file_path, line_num, category=category, pattern_name=pattern_name, match_text=match_text, context=context, enriched=None)
                                        except Exception:
                                            pass
                            else:
                                # No enricher installed: fallback behavior
                                match_info = {
                                    'type': f"{category}.{pattern_name}",
                                    'match': match_text,
                                    'line': line_num,
                                    'context': context
                                }
                                file_matches.append(match_info)
                                if category not in self.stats["matches_by_category"]:
                                    self.stats["matches_by_category"][category] = 0
                                self.stats["matches_by_category"][category] += 1
                                self.stats["num_matches_found"] += 1

                                if self.debug_flag or self.print_fallback:
                                    try:
                                        self._display_match(file_path, line_num, category=category, pattern_name=pattern_name, match_text=match_text, context=context, enriched=None)
                                    except Exception:
                                        pass

                            findings += 1
                            if findings >= 10:
                                self.results[file_path] = file_matches
                                return findings
                    except Exception as e:
                        self.logger.debug(f"Error searching pattern {pattern_name}: {e}")
                        continue

        if file_matches:
            self.results[file_path] = file_matches
            self.stats["files_with_matches"] += 1

        return findings

    def get_context(self, lines, center_line, context_lines):
        if context_lines == 0:
            return []
        start = max(0, center_line - context_lines)
        end = min(len(lines), center_line + context_lines + 1)
        ctx = []
        for i in range(start, end):
            if i != center_line:
                ctx.append(lines[i])
        return ctx

    def check_filename_for_credentials(self, filename, file_path):
        filename_lower = filename.lower()
        if filename_lower in self.system_files_to_ignore:
            if self.debug_flag:
                self.logger.debug(f"  Skipping system file: {filename}")
            return False
        for ext in self.ignore_extensions:
            if filename_lower.endswith(ext):
                if self.debug_flag:
                    self.logger.debug(f"  Skipping file with ignored extension: {filename}")
                return False
        if (filename_lower.startswith('~') or filename_lower.startswith('.tmp') or
                filename_lower.endswith('.tmp') or filename_lower.endswith('.temp') or
                filename_lower.endswith('.bak') or filename_lower.endswith('.old') or
                'thumbs.db' in filename_lower or 'desktop.ini' in filename_lower):
            if self.debug_flag:
                self.logger.debug(f"  Skipping temp/system pattern file: {filename}")
            return False

        for keyword in self.credential_filename_keywords:
            if keyword in filename_lower:
                if file_path not in self.results:
                    self.results[file_path] = []
                match_info = {
                    'type': 'filename.suspicious',
                    'match': f'Filename contains keyword: "{keyword}"',
                    'line': 0,
                    'context': [f'Full filename: {filename}']
                }
                self.results[file_path].append(match_info)
                if 'filename' not in self.stats["matches_by_category"]:
                    self.stats["matches_by_category"]['filename'] = 0
                self.stats["matches_by_category"]['filename'] += 1
                self.stats["num_matches_found"] += 1
                #self.logger.highlight(f"[FILENAME] {file_path}: Suspicious filename detected (keyword: '{keyword}')")
                return True
        return False

    def save_results(self):
        if not self.output_folder or not self.results:
            return
        try:
            from os import makedirs
            makedirs(self.output_folder, exist_ok=True)
            host = self.smb.conn.getRemoteHost()
            results_path = join(self.output_folder, f"{host}_credentials.json")
            filename_matches = {}
            content_matches = {}
            for file_path, matches in self.results.items():
                filename_matches[file_path] = []
                content_matches[file_path] = []
                for match in matches:
                    if match.get('type', '').startswith('filename.') or match.get('final_verdict', '').startswith('suspicious_filename'):
                        filename_matches[file_path].append(match)
                    else:
                        content_matches[file_path].append(match)
                if not filename_matches[file_path]:
                    del filename_matches[file_path]
                if not content_matches[file_path]:
                    del content_matches[file_path]
            output_data = {
                "target": host,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "statistics": self.stats,
                "suspicious_filenames": filename_matches,
                "content_matches": content_matches,
                "all_matches": self.results
            }
            with open(results_path, "w", encoding="utf-8") as fd:
                fd.write(json.dumps(output_data, indent=4, sort_keys=True, ensure_ascii=False))
            self.logger.success(f'Saved credential search results to "{results_path}".')
        except Exception as e:
            self.logger.fail(f"Failed to save results: {e}")

    def print_stats(self):
        if not self.stats_flag:
            return
        self.logger.display("=== Credential Search Statistics ===")
        shares = self.stats.get("shares", [])
        if shares:
            num_shares = len(shares)
            shares_str = ", ".join(shares[:5]) + ("..." if len(shares) > 5 else "")
            self.logger.display(f"SMB Shares:           {num_shares} ({shares_str})")
        shares_readable = self.stats.get("shares_readable", [])
        if shares_readable:
            num_readable = len(shares_readable)
            readable_str = ", ".join(shares_readable[:5]) + ("..." if len(shares_readable) > 5 else "")
            self.logger.display(f"SMB Readable Shares:  {num_readable} ({readable_str})")
        num_shares_filtered = self.stats.get("num_shares_filtered", 0)
        if num_shares_filtered:
            self.logger.display(f"SMB Filtered Shares:  {num_shares_filtered}")
        num_files = self.stats.get("num_files", 0)
        if num_files:
            self.logger.display(f"Total files found:    {num_files}")
        num_files_processed = self.stats.get("num_files_processed", 0)
        if num_files_processed:
            self.logger.display(f"Files processed:      {num_files_processed}")
        num_files_filtered = self.stats.get("num_files_filtered", 0)
        if num_files_filtered:
            self.logger.display(f"Files filtered:       {num_files_filtered}")
        num_matches = self.stats.get("num_matches_found", 0)
        files_with_matches = self.stats.get("files_with_matches", 0)
        if num_matches > 0:
            self.logger.display(f"Total matches found:  {num_matches}")
            self.logger.display(f"Files with matches:   {files_with_matches}")
            matches_by_category = self.stats.get("matches_by_category", {})
            if matches_by_category:
                self.logger.display("Matches by category:")
                for category, count in sorted(matches_by_category.items()):
                    if category == 'filename':
                        self.logger.highlight(f"  {category.capitalize():15}: {count} (suspicious filenames)")
                    else:
                        self.logger.display(f"  {category.capitalize():15}: {count}")
        if num_matches == 0:
            self.logger.display("No credential patterns found.")
        elif files_with_matches > 0:
            self.logger.success(f"Successfully found credentials in {files_with_matches} files!")

    def search_shares(self):
        self.logger.info("Starting credential search in SMB shares")
        shares_to_process = []
        if self.target_share:
            if self.debug_flag:
                self.logger.display(f'Testing access to target share: "{self.target_share}"')
            try:
                self.smb.conn.listPath(self.target_share, "*")
                self.stats["shares"].append(self.target_share)
                self.stats["shares_readable"].append(self.target_share)
                shares_to_process.append(self.target_share)
                if self.debug_flag:
                    self.logger.success(f'Target share "{self.target_share}" is accessible')
            except SessionError as e:
                if "STATUS_ACCESS_DENIED" in str(e):
                    self.logger.fail(f'Target share "{self.target_share}" - Access denied')
                elif "STATUS_BAD_NETWORK_NAME" in str(e):
                    self.logger.fail(f'Target share "{self.target_share}" - Share does not exist')
                else:
                    self.logger.fail(f'Cannot access target share "{self.target_share}": {e}')
                return
            except Exception as e:
                self.logger.fail(f'Error testing target share "{self.target_share}": {e}')
                return
        else:
            try:
                if self.debug_flag:
                    self.logger.display("Enumerating all shares...")
                shares_raw = self.smb.conn.listShares()
                if self.debug_flag:
                    self.logger.success(f"Enumerated {len(shares_raw)} shares")
                for share in shares_raw:
                    share_name = share["shi1_netname"][:-1]
                    share_remark = share["shi1_remark"][:-1] if share["shi1_remark"] else ""
                    self.stats["shares"].append(share_name)
                    if self.debug_flag:
                        if share_remark.strip():
                            self.logger.display(f'Found share: "{share_name}" - {share_remark}')
                        else:
                            self.logger.display(f'Found share: "{share_name}"')
                    try:
                        self.smb.conn.listPath(share_name, "*")
                        self.stats["shares_readable"].append(share_name)
                        shares_to_process.append(share_name)
                        if self.debug_flag:
                            self.logger.display(f'Share "{share_name}" is accessible')
                    except SessionError as e:
                        if self.debug_flag and "STATUS_ACCESS_DENIED" in str(e):
                            self.logger.display(f'Share "{share_name}" - Access denied')
                        elif self.debug_flag:
                            self.logger.debug(f"Cannot access share {share_name}: {e}")
                        continue
            except Exception as e:
                self.logger.fail(f"Failed to enumerate shares: {e}")
                return

        if not self.debug_flag and len(shares_to_process) > 0:
            self.logger.info(f"Scanning {len(shares_to_process)} accessible shares for credentials...")
        elif self.debug_flag:
            self.logger.display(f"Starting to process {len(shares_to_process)} accessible shares...")

        total_findings = 0
        processed_shares = 0
        for share_name in shares_to_process:
            try:
                if self.debug_flag:
                    self.logger.display(f'[{processed_shares+1}/{len(shares_to_process)}] Processing share: "{share_name}"')
                elif not self.debug_flag:
                    self.logger.info(f'Scanning share: "{share_name}"')
                if share_name.upper() in ['ADMIN$', 'C$', 'IPC$'] and not self.target_share:
                    if self.debug_flag:
                        self.logger.info(f'Share "{share_name}" excluded (system share)')
                    self.stats["num_shares_filtered"] += 1
                    continue
                try:
                    start_folder = ""
                    if self.target_folder and share_name == self.target_share:
                        start_folder = self.target_folder.strip()
                        if start_folder and not start_folder.endswith("/"):
                            start_folder += "/"
                        if self.debug_flag:
                            self.logger.display(f'Starting from specific folder: "{start_folder}"')
                    findings = self.spider_folder(share_name, start_folder, 0)
                    total_findings += findings
                    processed_shares += 1
                    if findings > 0:
                        self.logger.success(f'Share "{share_name}" - Found {findings} credentials!')
                    elif self.debug_flag:
                        self.logger.display(f'Share "{share_name}" completed - No credentials found')
                except (SessionError, NetBIOSTimeout) as e:
                    self.logger.fail(f'Network error in share "{share_name}": {str(e)[:100]}...')
                    if not self.reconnect():
                        self.logger.fail("Failed to reconnect. Stopping search.")
                        break
                except Exception as e:
                    self.logger.fail(f'Error in share "{share_name}": {str(e)[:100]}...')
                    continue
            except Exception as e:
                self.logger.fail(f'Critical error processing share "{share_name}": {e}')
                continue

        self.stats["num_matches_found"] = total_findings
        if self.debug_flag:
            self.logger.display(f"Processed {processed_shares} shares successfully")
        if self.output_folder and self.results:
            self.save_results()
        if self.stats_flag and self.debug_flag:
            self.print_stats()
        if total_findings > 0:
            self.logger.success(f"Credential search completed! Found {total_findings} potential credentials in {self.stats['files_with_matches']} files")
        else:
            self.logger.info(f"Credential search completed. No credentials found in target location")

    def spider_folder(self, share_name, folder, depth):
        if depth > self.max_depth:
            self.logger.debug(f"Maximum depth ({self.max_depth}) reached for folder: {folder}")
            return 0
        folder_display = folder if folder else "/"
        if self.debug_flag:
            self.logger.display(f'  Exploring folder "{folder_display}" in share "{share_name}" (depth: {depth})')
        skip_folders = ['$RECYCLE.BIN', 'System Volume Information', 'Config.Msi', 'Recovery']
        folder_name = folder.strip('/')
        if any(skip_folder.lower() in folder_name.lower() for skip_folder in skip_folders):
            if self.debug_flag:
                self.logger.display(f'  Skipping system folder "{folder_display}"')
            return 0
        try:
            filelist = self.list_path(share_name, folder)
            if not filelist:
                if self.debug_flag:
                    self.logger.display(f"  No items found in folder {folder_display}")
                return 0
            if self.debug_flag:
                self.logger.display(f"  Found {len(filelist)} items in folder {folder_display}")
        except Exception as e:
            if self.debug_flag:
                self.logger.fail(f'  Failed to list folder "{folder_display}": {str(e)[:50]}...')
            return 0

        total_findings = 0
        files_processed = 0
        dirs_processed = 0

        if depth == 0:
            max_files = None
        elif depth == 1:
            max_files = 50
        else:
            max_files = 25

        for result in filelist:
            if max_files and files_processed >= max_files:
                if self.debug_flag:
                    self.logger.display(f"  File limit ({max_files}) reached in folder {folder_display}")
                break
            try:
                next_filedir = result.get_longname()
                if next_filedir in [".", ".."]:
                    continue
                if not result.is_directory():
                    self.stats["num_files"] += 1
                    current_path = folder + next_filedir if folder != "" else next_filedir
                    filename_suspicious = self.check_filename_for_credentials(next_filedir, f"{share_name}/{current_path}")
                    if filename_suspicious:
                        total_findings += 1
                        if f"{share_name}/{current_path}" not in [path for path in self.results.keys()]:
                            self.stats["files_with_matches"] += 1
                    if any(next_filedir.lower().endswith(ext) for ext in self.file_extensions):
                        file_lower = next_filedir.lower()
                        if any(pattern in file_lower for pattern in self.skip_file_patterns):
                            if self.debug_flag:
                                self.logger.debug(f"  Skipping data file: {next_filedir}")
                            self.stats["num_files_filtered"] += 1
                            continue
                        file_size = result.get_filesize()
                        if file_size > 1024 * 1024:
                            if self.debug_flag:
                                self.logger.debug(f"  Skipping large file: {next_filedir} ({file_size} bytes)")
                            self.stats["num_files_filtered"] += 1
                            continue
                        content_findings = self.parse_file(share_name, current_path, result)
                        total_findings += content_findings
                        files_processed += 1
                        self.stats["num_files_processed"] += 1
                    else:
                        if not filename_suspicious:
                            self.stats["num_files_filtered"] += 1
            except Exception as e:
                self.logger.debug(f"Error processing file in {share_name}{folder_display}: {e}")
                continue

        if depth == 0:
            max_dirs = None
        elif depth == 1:
            max_dirs = 50
        else:
            max_dirs = 10

        for result in filelist:
            if max_dirs and dirs_processed >= max_dirs:
                if self.debug_flag:
                    self.logger.display(f"  Directory limit ({max_dirs}) reached in folder {folder_display}")
                break
            try:
                next_filedir = result.get_longname()
                if next_filedir in [".", ".."]:
                    continue
                if result.is_directory():
                    if any(skip_folder.lower() in next_filedir.lower() for skip_folder in skip_folders):
                        if self.debug_flag:
                            self.logger.display(f'  Skipping system directory: "{next_filedir}"')
                        continue
                    next_folder = folder + next_filedir + "/" if folder != "" else next_filedir + "/"
                    if self.debug_flag:
                        self.logger.display(f'  Entering subfolder: "{next_folder}"')
                    try:
                        subfolder_findings = self.spider_folder(share_name, next_folder, depth + 1)
                        total_findings += subfolder_findings
                        dirs_processed += 1
                    except Exception as e:
                        self.logger.debug(f"Error in subfolder {next_folder}: {e}")
                        continue
            except Exception as e:
                self.logger.debug(f"Error processing directory in {share_name}{folder_display}: {e}")
                continue

        if self.debug_flag and (files_processed > 0 or dirs_processed > 0 or total_findings > 0):
            status = f'{files_processed} files, {dirs_processed} dirs processed'
            if total_findings > 0:
                status += f', {total_findings} credentials found'
            else:
                status += ', no credentials'
            if depth == 0:
                status += ' (complete scan - no limits)'
            self.logger.display(f'  Completed folder "{folder_display}": {status}')
        return total_findings

    def parse_file(self, share_name, file_path, file_info):
        file_size = file_info.get_filesize()
        if self.debug_flag:
            size_display = f" ({file_size} bytes)" if file_size > 0 else " (0 bytes)"
            self.logger.display(f'    Processing: {file_path}{size_display}')
        if file_size > self.max_file_size:
            if self.debug_flag:
                self.logger.display(f"      [SKIPPED] File too large (max: {self.max_file_size} bytes)")
            return 0
        if file_size == 0:
            if self.debug_flag:
                self.logger.display(f"      [SKIPPED] File is empty")
            return 0

        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                remote_file = self.get_remote_file(share_name, file_path)
                if not remote_file:
                    if attempt < max_retries:
                        self.logger.debug(f'      Retrying file access (attempt {attempt + 1}/{max_retries + 1})')
                        time.sleep(1)
                        continue
                    else:
                        if self.debug_flag:
                            self.logger.display(f'      [ERROR] Cannot access file after {max_retries + 1} attempts')
                        return 0

                remote_file.open_file()

                if file_size > 512 * 1024:
                    content_bytes = b""
                    chunk_size = 64 * 1024
                    bytes_read = 0
                    while bytes_read < file_size:
                        try:
                            remaining = min(chunk_size, file_size - bytes_read)
                            chunk = remote_file.read(remaining)
                            if not chunk:
                                break
                            content_bytes += chunk
                            bytes_read += len(chunk)
                            if bytes_read >= 100 * 1024:
                                self.logger.debug(f"      Read {bytes_read} bytes (truncated for performance)")
                                break
                        except Exception as chunk_error:
                            self.logger.debug(f"      Chunk read error at {bytes_read} bytes: {chunk_error}")
                            break
                    content = content_bytes
                else:
                    content = remote_file.read(file_size)

                remote_file.close()

                if isinstance(content, bytes):
                    for encoding in ['utf-8', 'latin-1', 'cp1252', 'ascii']:
                        try:
                            content = content.decode(encoding)
                            break
                        except UnicodeDecodeError:
                            continue
                    else:
                        content = content.decode('utf-8', errors='ignore')

                findings = self.search_patterns_in_content(content, f"{share_name}/{file_path}")
                self.consecutive_network_errors = 0

                if findings > 0:
                    self.logger.success(f"[FOUND] {file_path}: {findings} credential(s) detected!")
                elif self.debug_flag:
                    self.logger.display(f"      [CLEAN] No credentials found")

                return findings

            except SessionError as e:
                error_str = str(e)
                if "STATUS_SHARING_VIOLATION" in error_str:
                    if self.debug_flag:
                        self.logger.display(f'      [ERROR] File locked (sharing violation)')
                    return 0
                elif "STATUS_ACCESS_DENIED" in error_str:
                    if self.debug_flag:
                        self.logger.display(f'      [ERROR] Access denied')
                    return 0
                else:
                    if attempt < max_retries:
                        self.logger.debug(f'      Network error (attempt {attempt + 1}), retrying: {error_str[:30]}...')
                        time.sleep(2)
                        if not self.reconnect():
                            if self.debug_flag:
                                self.logger.display(f'      [ERROR] Failed to reconnect')
                            return 0
                        continue
                    else:
                        if self.debug_flag:
                            self.logger.display(f'      [ERROR] Session error after retries: {error_str[:50]}...')
                        return 0
            except (NetBIOSTimeout, OSError, ConnectionError) as e:
                error_str = str(e)
                self.consecutive_network_errors += 1
                if "Broken pipe" in error_str or "Connection reset" in error_str or "timed out" in error_str:
                    if attempt < max_retries:
                        self.logger.debug(f'      Connection error (attempt {attempt + 1}), retrying: {error_str[:30]}...')
                        if self.consecutive_network_errors >= self.max_consecutive_errors:
                            if self.debug_flag:
                                self.logger.display(f'      [WARNING] Too many network errors, pausing 10 seconds...')
                            time.sleep(10)
                            self.consecutive_network_errors = 0
                        else:
                            time.sleep(2)
                        if not self.reconnect():
                            if self.debug_flag:
                                self.logger.display(f'      [ERROR] Failed to reconnect')
                            return 0
                        continue
                    else:
                        if self.debug_flag:
                            self.logger.display(f'      [ERROR] Connection failed after retries: {error_str[:50]}...')
                        return 0
                else:
                    if self.debug_flag:
                        self.logger.display(f'      [ERROR] Network error: {error_str[:50]}...')
                    return 0
            except Exception as e:
                error_str = str(e)
                if attempt < max_retries and ("Connection" in error_str or "timeout" in error_str or "pipe" in error_str):
                    self.logger.debug(f'      Unexpected error (attempt {attempt + 1}), retrying: {error_str[:30]}...')
                    time.sleep(1)
                    continue
                else:
                    if self.debug_flag:
                        self.logger.display(f'      [ERROR] Read error: {error_str[:50]}...')
                    return 0

        return 0


def get_list_from_option(opt):
    return [o.lower().strip() for o in filter(bool, opt.split(","))]


class NXCModule:
    name = 'search_passwords'
    description = "Enhanced search for passwords and credentials in SMB files using categorized regex patterns with context and statistics"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        # Normalize keys to uppercase so we accept SHARE, share, Share, etc.
        normalized_opts = {str(k).upper(): v for k, v in (module_options or {}).items()}

        self.target_share = None
        self.target_folder = None
        self.max_file_size = 2 * 1024 * 1024
        self.max_depth = 4
        self.pattern_types = None
        self.context_lines = 2
        self.stats_flag = True
        self.debug_flag = False
        self.print_fallback = True
        self.output_folder = abspath(join(NXC_PATH, "modules/nxc_search_passwords"))

        validation_errors = []

        # Read options from normalized keys
        if "SHARE" in normalized_opts:
            self.target_share = normalized_opts["SHARE"]
        if "FOLDER" in normalized_opts:
            self.target_folder = normalized_opts["FOLDER"]
        if CUSTOM_FOLDER is not None:
            self.target_folder = CUSTOM_FOLDER
            context.log.display(f"Using custom FOLDER: {CUSTOM_FOLDER}")
        if "MAX_FILE_SIZE" in normalized_opts:
            try:
                self.max_file_size = int(normalized_opts["MAX_FILE_SIZE"])
            except ValueError:
                validation_errors.append(f"Invalid MAX_FILE_SIZE value: {normalized_opts['MAX_FILE_SIZE']} (must be a number)")
        if "DEPTH" in normalized_opts:
            try:
                self.max_depth = int(normalized_opts["DEPTH"])
            except ValueError:
                validation_errors.append(f"Invalid DEPTH value: {normalized_opts['DEPTH']} (must be a number)")
        if "PATTERN_TYPES" in normalized_opts:
            pattern_types_str = normalized_opts["PATTERN_TYPES"]
            if isinstance(pattern_types_str, str) and pattern_types_str.lower() != 'all':
                self.pattern_types = get_list_from_option(pattern_types_str)
        if "CONTEXT_LINES" in normalized_opts:
            try:
                self.context_lines = int(normalized_opts["CONTEXT_LINES"])
            except ValueError:
                validation_errors.append(f"Invalid CONTEXT_LINES value: {normalized_opts['CONTEXT_LINES']} (must be a number)")
        if "STATS_FLAG" in normalized_opts:
            self.stats_flag = str(normalized_opts["STATS_FLAG"]).lower() in ['true', '1', 'yes', 'on']
        if "DEBUG" in normalized_opts:
            self.debug_flag = str(normalized_opts["DEBUG"]).lower() in ['true', '1', 'yes', 'on']
        if "OUTPUT_FOLDER" in normalized_opts:
            self.output_folder = normalized_opts["OUTPUT_FOLDER"]
        if "PRINT_FALLBACK" in normalized_opts:
            self.print_fallback = str(normalized_opts["PRINT_FALLBACK"]).lower() in ['true', '1', 'yes', 'on']

        # Validation: FOLDER requires SHARE
        if self.target_folder and not self.target_share:
            validation_errors.append("FOLDER option requires SHARE to be specified")
            validation_errors.append("Example: -o SHARE=C$ -o FOLDER=Users")
            self.target_folder = None

        if validation_errors:
            for error in validation_errors:
                context.log.fail(error)
            context.log.display("Using default values for invalid parameters.")
            context.log.display("Valid examples: -o MAX_FILE_SIZE=5242880 -o DEPTH=4 -o CONTEXT_LINES=2")

        # Show parsed options for debugging
        if len(module_options) > 0:
            context.log.display(f"Parsed {len(module_options)} module option(s):")
            for key, value in module_options.items():
                context.log.display(f"  {key} = {value}")

    def on_login(self, context, connection):
        context.log.display("Started enhanced credential search with the following options:")
        if self.debug_flag:
            context.log.display(f"TARGET_SHARE:     {self.target_share if self.target_share else 'All accessible shares'}")
            context.log.display(f"TARGET_FOLDER:    {self.target_folder if self.target_folder else 'Root folder'}")
            context.log.display(f"MAX_FILE_SIZE:    {self.max_file_size // (1024*1024)}MB")
            context.log.display(f"DEPTH:            {self.max_depth}")
            context.log.display(f"PATTERN_TYPES:    {', '.join(self.pattern_types) if self.pattern_types else 'all'}")
            context.log.display(f"CONTEXT_LINES:    {self.context_lines}")
            context.log.display(f"STATS_FLAG:       {self.stats_flag}")
            context.log.display(f"DEBUG:            {self.debug_flag}")
            context.log.display(f"PRINT_FALLBACK:   {self.print_fallback}")
            context.log.display(f"OUTPUT_FOLDER:    {self.output_folder}")
        else:
            context.log.info("Starting enhanced credential search...")

        searcher = SMBCredentialSearcher(
            connection,
            context.log,
            self.target_share,
            self.target_folder,
            self.max_file_size,
            self.max_depth,
            self.pattern_types,
            self.context_lines,
            self.output_folder,
            self.stats_flag,
            self.debug_flag,
            self.print_fallback
        )

        searcher.search_shares()
