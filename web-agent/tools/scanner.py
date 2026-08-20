import os
import subprocess
import shutil


def _run(cmd: list[str], timeout: int = 120) -> str:
    tool = cmd[0]
    if not shutil.which(tool):
        return f"Error: '{tool}' is not installed. Install it and retry."
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = (result.stdout + result.stderr).strip()
        return output if output else "(no output)"
    except subprocess.TimeoutExpired:
        return f"Error: '{tool}' timed out after {timeout}s"
    except Exception as e:
        return f"Error running '{tool}': {e}"


def port_scan(target: str, ports: str = "", flags: str = "") -> str:
    """nmap port scan with service/version detection."""
    cmd = ["nmap", "-sV", "-sC", "--open"]
    if ports:
        cmd += ["-p", ports]
    if flags:
        cmd += flags.split()
    cmd.append(target)
    return _run(cmd, timeout=180)


def web_fingerprint(target: str) -> str:
    """whatweb — identify web technologies, frameworks, CMS."""
    url = target if target.startswith("http") else f"http://{target}"
    return _run(["whatweb", "-a", "3", url], timeout=60)


def web_scan(target: str) -> str:
    """nikto — web server misconfiguration and vulnerability scan."""
    url = target if target.startswith("http") else f"http://{target}"
    return _run(["nikto", "-h", url, "-nointeractive"], timeout=300)


def vuln_scan(target: str, templates: str = "") -> str:
    """nuclei — template-based vulnerability scanner."""
    url = target if target.startswith("http") else f"http://{target}"
    cmd = ["nuclei", "-u", url, "-severity", "low,medium,high,critical", "-silent"]
    if templates:
        cmd += ["-t", templates]
    return _run(cmd, timeout=300)


_DEFAULT_WORDLIST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "wordlists", "common.txt",
)


def dir_enum(target: str, wordlist: str = "", extensions: str = "php,html,js,txt,bak") -> str:
    """gobuster — brute-force directories and files."""
    url = target if target.startswith("http") else f"http://{target}"
    wl = wordlist or _DEFAULT_WORDLIST
    cmd = ["gobuster", "dir", "-u", url, "-w", wl, "-x", extensions, "-q", "--no-error"]
    return _run(cmd, timeout=300)


def exploit_search(query: str) -> str:
    """searchsploit — search Exploit-DB for known exploits matching a service/version."""
    return _run(["searchsploit", "--color", query], timeout=30)
