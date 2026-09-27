"""Passive email-authentication checks: SPF, DMARC, DKIM, MX, DNSSEC.
Every check here is a read-only DNS lookup. Nothing is sent to the domain itself.
"""

from __future__ import annotations
import dns.resolver
import dns.exception
from models import Finding, Severity

COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "google", "k1", "s1", "mail"]


class DnsLookupError(Exception):
    """The lookup itself failed (timeout) — not the same as the record being absent."""


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = 4
    r.lifetime = 8
    r.use_edns(0, 0, 4096)  # avoids false "missing" results on large TXT records
    return r


def _query_txt(resolver, name: str) -> list[str]:
    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
        raise DnsLookupError(str(e)) from e
    records = []
    for rdata in answers:
        parts = [s.decode("utf-8", "replace") if isinstance(s, bytes) else s for s in rdata.strings]
        records.append("".join(parts))
    return records


def check_spf(resolver, domain: str) -> list[Finding]:
    try:
        txts = _query_txt(resolver, domain)
    except DnsLookupError:
        return [Finding("spf_lookup_failed", "email_auth", Severity.INFO,
                         "Could not complete SPF lookup",
                         f"DNS lookup for {domain} timed out. Unverified, not confirmed absent.")]
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spf:
        return [Finding("spf_missing", "email_auth", Severity.HIGH,
                         "No SPF record found",
                         f"{domain} has no SPF record, so mail servers can't verify who's allowed to send as this domain.",
                         "Publish an SPF TXT record ending in '-all'.")]
    if spf[0].rstrip().endswith("-all"):
        return [Finding("spf_strict", "email_auth", Severity.INFO, "SPF present with a strict policy", domain, passed=True)]
    return [Finding("spf_weak", "email_auth", Severity.LOW, "SPF present but not strict",
                     f"{domain}'s SPF doesn't hard-fail unauthorized senders.",
                     "Tighten to '-all' once all senders are confirmed.")]


def check_dmarc(resolver, domain: str) -> list[Finding]:
    try:
        txts = _query_txt(resolver, f"_dmarc.{domain}")
    except DnsLookupError:
        return [Finding("dmarc_lookup_failed", "email_auth", Severity.INFO,
                         "Could not complete DMARC lookup",
                         f"DNS lookup for _dmarc.{domain} timed out. Unverified, not confirmed absent.")]
    dmarc = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        return [Finding("dmarc_missing", "email_auth", Severity.CRITICAL,
                         "No DMARC record found",
                         f"{domain} has no DMARC policy, so failed mail still gets delivered.",
                         f"Publish a DMARC record at _dmarc.{domain} starting with p=none.")]
    policy = next((p.split("=", 1)[1].strip().lower() for p in dmarc[0].split(";")
                   if p.strip().lower().startswith("p=")), None)
    labels = {"reject": (Severity.INFO, "DMARC set to reject", True),
              "quarantine": (Severity.LOW, "DMARC set to quarantine", False),
              "none": (Severity.HIGH, "DMARC set to none (monitor only)", False)}
    sev, title, passed = labels.get(policy, (Severity.MEDIUM, "DMARC policy unclear", False))
    return [Finding("dmarc_policy", "email_auth", sev, title, f"{domain}: p={policy}", passed=passed)]


def check_dkim(resolver, domain: str) -> list[Finding]:
    found = []
    for sel in COMMON_DKIM_SELECTORS:
        try:
            txts = _query_txt(resolver, f"{sel}._domainkey.{domain}")
        except DnsLookupError:
            continue
        if any("v=dkim1" in t.lower() or "p=" in t.lower() for t in txts):
            found.append(sel)
    if found:
        return [Finding("dkim_found", "email_auth", Severity.INFO, "DKIM record found", ", ".join(found), passed=True)]
    return [Finding("dkim_not_found", "email_auth", Severity.LOW, "No DKIM found under common selectors",
                     f"Inconclusive for {domain} — many providers use custom selector names.")]


def run_all(domain: str) -> list[Finding]:
    resolver = _resolver()
    findings = []
    findings += check_spf(resolver, domain)
    findings += check_dmarc(resolver, domain)
    findings += check_dkim(resolver, domain)
    return findings


if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Domain to check: ")
    for f in run_all(domain):
        print(f"[{f.severity.value.upper()}] {f.title} — {f.detail}")