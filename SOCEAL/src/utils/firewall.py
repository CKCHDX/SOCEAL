"""
SOCeal - Project VALE
Firewall Helpers: Windows Firewall management via netsh.
"""

import subprocess
import logging
import re

logger = logging.getLogger('soceal.utils.firewall')

RULE_PREFIX = 'SOCeal_Block_'


def _run_netsh(args, timeout=10):
    """Run a netsh command and return (success, stdout, stderr)."""
    cmd = ['netsh'] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        logger.error("netsh command timed out: %s", ' '.join(cmd))
        return False, '', 'Timeout'
    except FileNotFoundError:
        logger.error("netsh not found -- is this Windows?")
        return False, '', 'netsh not found'


def add_block_rule(ip, rule_name=None):
    """
    Add a firewall rule to block inbound traffic from an IP.

    Returns:
        bool: True if rule was added successfully.
    """
    name = rule_name or f"{RULE_PREFIX}{ip}"
    success, out, err = _run_netsh([
        'advfirewall', 'firewall', 'add', 'rule',
        f'name={name}', 'dir=in', 'action=block', f'remoteip={ip}',
    ])
    if success:
        logger.info("Firewall rule added: %s (block %s)", name, ip)
    else:
        logger.error("Failed to add firewall rule for %s: %s", ip, err)
    return success


def remove_block_rule(ip):
    """
    Remove a SOCeal firewall block rule for an IP.

    Returns:
        bool: True if rule was removed successfully.
    """
    name = f"{RULE_PREFIX}{ip}"
    success, out, err = _run_netsh([
        'advfirewall', 'firewall', 'delete', 'rule', f'name={name}',
    ])
    if success:
        logger.info("Firewall rule removed: %s", name)
    else:
        logger.error("Failed to remove firewall rule %s: %s", name, err)
    return success


def list_soceal_rules():
    """
    List all SOCeal firewall rules.

    Returns:
        list[str]: Rule names matching the SOCeal prefix.
    """
    success, out, err = _run_netsh([
        'advfirewall', 'firewall', 'show', 'rule', f'name=all',
    ])
    if not success:
        logger.error("Failed to list firewall rules: %s", err)
        return []

    rules = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('Rule Name:'):
            name = line.split(':', 1)[1].strip()
            if name.startswith(RULE_PREFIX):
                rules.append(name)
    return rules


def cleanup_all_rules():
    """
    Remove all SOCeal firewall rules.

    Returns:
        int: Number of rules removed.
    """
    rules = list_soceal_rules()
    removed = 0
    for rule_name in rules:
        success, _, _ = _run_netsh([
            'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}',
        ])
        if success:
            removed += 1
    logger.info("Cleaned up %d/%d SOCeal firewall rules", removed, len(rules))
    return removed


def get_blocked_ip_count():
    """Return the number of currently blocked IPs via SOCeal rules."""
    return len(list_soceal_rules())
