"""
Prevention service for NIDS-XAI.

Modes:
  monitor  — log only, no blocking
  dry_run  — log what *would* happen, no actual blocking
  enforce  — call iptables to drop traffic from the offending IP

Only calls iptables inside _block_with_iptables() / _unblock_with_iptables(),
which are ONLY reached when ENFORCEMENT_MODE == "enforce".

Auto-expires blocks after BLOCK_TTL_SECONDS.
Keeps an IP whitelist (never blocks whitelisted IPs).
Logs every action with reason.
"""

import logging
import threading
import time
import subprocess
from typing import Dict, List, Optional

from config.config import ENFORCEMENT_MODE, BLOCK_TTL_SECONDS, IP_WHITELIST, IPTABLES_CHAIN

logger = logging.getLogger(__name__)

_VALID_MODES = {"monitor", "dry_run", "enforce"}


class PreventionService:
    def __init__(self):
        self._lock = threading.Lock()
        # ip -> {blocked_at: float, ttl: int, reason: str}
        self._blocked: Dict[str, dict] = {}
        self._mode = ENFORCEMENT_MODE if ENFORCEMENT_MODE in _VALID_MODES else "dry_run"
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="prevention-cleanup"
        )
        self._cleanup_thread.start()
        logger.info("PreventionService started in mode=%s", self._mode)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    @property
    def mode(self) -> str:
        return self._mode

    def set_mode(self, mode: str) -> None:
        """Change enforcement mode at runtime."""
        if mode not in _VALID_MODES:
            raise ValueError(f"Invalid mode '{mode}'. Must be one of {_VALID_MODES}.")
        with self._lock:
            old = self._mode
            self._mode = mode
        logger.warning("PreventionService mode changed: %s -> %s", old, mode)

    def block_ip(self, ip: str, reason: str, ttl: Optional[int] = None) -> dict:
        """
        Block an IP address.

        Respects the current mode and the IP whitelist.
        Returns a dict describing the action taken.
        """
        effective_ttl = ttl if ttl is not None else BLOCK_TTL_SECONDS

        if ip in IP_WHITELIST:
            msg = f"[{self._mode}] SKIP block {ip} — whitelisted. reason={reason}"
            logger.info(msg)
            return {"action": "skipped", "ip": ip, "reason": "whitelisted", "mode": self._mode}

        with self._lock:
            already = ip in self._blocked
            if not already:
                self._blocked[ip] = {
                    "ip": ip,
                    "blocked_at": time.time(),
                    "ttl": effective_ttl,
                    "reason": reason,
                }

        if already:
            logger.info("[%s] %s already blocked (TTL refreshed). reason=%s", self._mode, ip, reason)
            # Refresh TTL
            with self._lock:
                self._blocked[ip]["blocked_at"] = time.time()
                self._blocked[ip]["ttl"] = effective_ttl
                self._blocked[ip]["reason"] = reason
            return {"action": "refreshed", "ip": ip, "ttl": effective_ttl, "mode": self._mode}

        if self._mode == "enforce":
            self._block_with_iptables(ip)
            logger.warning("[enforce] BLOCKED %s via iptables. reason=%s ttl=%ds", ip, reason, effective_ttl)
            action = "blocked_iptables"
        elif self._mode == "dry_run":
            logger.info("[dry_run] WOULD block %s. reason=%s ttl=%ds", ip, reason, effective_ttl)
            action = "dry_run_blocked"
        else:  # monitor
            logger.info("[monitor] ALERT: would block %s. reason=%s ttl=%ds", ip, reason, effective_ttl)
            action = "logged"

        return {"action": action, "ip": ip, "ttl": effective_ttl, "reason": reason, "mode": self._mode}

    def unblock_ip(self, ip: str) -> dict:
        """
        Unblock an IP address.

        Returns a dict describing the action taken.
        """
        with self._lock:
            entry = self._blocked.pop(ip, None)

        if entry is None:
            logger.info("unblock_ip: %s was not blocked", ip)
            return {"action": "not_found", "ip": ip}

        if self._mode == "enforce":
            self._unblock_with_iptables(ip)
            logger.warning("[enforce] UNBLOCKED %s via iptables.", ip)
            action = "unblocked_iptables"
        elif self._mode == "dry_run":
            logger.info("[dry_run] WOULD unblock %s.", ip)
            action = "dry_run_unblocked"
        else:
            logger.info("[monitor] ALERT: would unblock %s.", ip)
            action = "logged"

        return {"action": action, "ip": ip, "mode": self._mode}

    def get_blocked(self) -> List[dict]:
        """Return list of currently blocked IPs with metadata."""
        now = time.time()
        with self._lock:
            result = []
            for ip, meta in self._blocked.items():
                elapsed = now - meta["blocked_at"]
                remaining = max(0.0, meta["ttl"] - elapsed)
                result.append({
                    "ip": ip,
                    "reason": meta["reason"],
                    "blocked_at": meta["blocked_at"],
                    "ttl": meta["ttl"],
                    "expires_in_seconds": round(remaining, 1),
                })
        return result

    # ------------------------------------------------------------------ #
    #  iptables helpers (only reached in enforce mode)                    #
    # ------------------------------------------------------------------ #

    def _block_with_iptables(self, ip: str) -> None:
        """
        ONLY called in enforce mode.
        Creates NIDS_BLOCK chain if it doesn't exist, then adds a DROP rule.
        """
        try:
            # Ensure chain exists
            subprocess.run(
                ["iptables", "-N", IPTABLES_CHAIN],
                capture_output=True, check=False,  # -N errors if chain already exists; ignore
            )
            # Jump to chain from INPUT if not already hooked
            subprocess.run(
                ["iptables", "-C", "INPUT", "-j", IPTABLES_CHAIN],
                capture_output=True, check=False,
            )
            ret = subprocess.run(
                ["iptables", "-C", "INPUT", "-j", IPTABLES_CHAIN],
                capture_output=True,
            )
            if ret.returncode != 0:
                subprocess.run(
                    ["iptables", "-I", "INPUT", "1", "-j", IPTABLES_CHAIN],
                    capture_output=True, check=True,
                )
            # Add DROP rule for IP
            subprocess.run(
                ["iptables", "-A", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"],
                check=True,
            )
        except Exception as exc:
            logger.error("iptables block failed for %s: %s", ip, exc)

    def _unblock_with_iptables(self, ip: str) -> None:
        """
        ONLY called in enforce mode.
        Removes the DROP rule for this IP from NIDS_BLOCK chain.
        """
        try:
            subprocess.run(
                ["iptables", "-D", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"],
                check=True,
            )
        except Exception as exc:
            logger.error("iptables unblock failed for %s: %s", ip, exc)

    # ------------------------------------------------------------------ #
    #  Background TTL cleanup                                             #
    # ------------------------------------------------------------------ #

    def _cleanup_loop(self) -> None:
        """Background daemon thread: expire blocks after their TTL."""
        while True:
            time.sleep(10)  # check every 10 s
            try:
                now = time.time()
                expired = []
                with self._lock:
                    for ip, meta in list(self._blocked.items()):
                        if now - meta["blocked_at"] >= meta["ttl"]:
                            expired.append(ip)
                for ip in expired:
                    logger.info("TTL expired for blocked IP %s — auto-unblocking.", ip)
                    self.unblock_ip(ip)
            except Exception as exc:
                logger.error("prevention cleanup loop error: %s", exc)


# Module-level singleton
prevention_service = PreventionService()
