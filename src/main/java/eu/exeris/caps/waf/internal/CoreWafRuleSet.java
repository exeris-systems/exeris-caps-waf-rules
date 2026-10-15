package eu.exeris.caps.waf.internal;

import eu.exeris.caps.waf.api.WafCategory;
import eu.exeris.caps.waf.api.WafRule;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The built-in rule set: a small list of case-insensitive substring keywords covering SQL injection,
 * cross-site scripting, path traversal and command execution.
 *
 * <p>It does not match regular expressions, and it sees encodings only as far as percent-decoding and
 * {@code +} for space; other encodings and obfuscations are not recognised.
 *
 * @since 0.1.0
 */
public final class CoreWafRuleSet {

    private static final List<WafRule> DEFAULT_RULES;

    static {
        List<WafRule> r = new ArrayList<>();

        // --- SQL Injection (SQLi) ---
        r.add(new WafRule("SQLI-101", "SQL Injection - UNION SELECT", WafCategory.SQL_INJECTION, "union select", "Detects classic SQL injection UNION query"));
        r.add(new WafRule("SQLI-102", "SQL Injection - UNION ALL SELECT", WafCategory.SQL_INJECTION, "union all select", "Detects UNION ALL SELECT injection"));
        r.add(new WafRule("SQLI-103", "SQL Injection - OR 1=1 boolean tautology", WafCategory.SQL_INJECTION, "or 1=1", "Detects boolean-based SQL tautology bypass"));
        r.add(new WafRule("SQLI-104", "SQL Injection - OR '1'='1' string tautology", WafCategory.SQL_INJECTION, "' or '1'='1", "Detects string-quoted SQL tautology"));
        r.add(new WafRule("SQLI-105", "SQL Injection - OR \"1\"=\"1\"", WafCategory.SQL_INJECTION, "\" or \"1\"=\"1", "Detects double-quoted SQL tautology"));
        r.add(new WafRule("SQLI-106", "SQL Injection - Schema enumeration", WafCategory.SQL_INJECTION, "information_schema", "Detects database schema inspection attempt"));
        r.add(new WafRule("SQLI-107", "SQL Injection - DROP TABLE command", WafCategory.SQL_INJECTION, "drop table", "Detects destructive SQL table drop statement"));
        r.add(new WafRule("SQLI-108", "SQL Injection - Sleep timing probe", WafCategory.SQL_INJECTION, "sleep(", "Detects time-based blind SQL injection probe"));
        r.add(new WafRule("SQLI-109", "SQL Injection - Benchmark timing probe", WafCategory.SQL_INJECTION, "benchmark(", "Detects MySQL benchmark timing probe"));

        // --- Cross-Site Scripting (XSS) ---
        r.add(new WafRule("XSS-201", "XSS - Script tag injection", WafCategory.XSS, "<script", "Detects inline script HTML tag injection"));
        r.add(new WafRule("XSS-202", "XSS - Script closing tag", WafCategory.XSS, "</script>", "Detects closing script HTML tag"));
        r.add(new WafRule("XSS-203", "XSS - JavaScript URI scheme", WafCategory.XSS, "javascript:", "Detects javascript pseudo-protocol handler"));
        r.add(new WafRule("XSS-204", "XSS - Event handler onerror", WafCategory.XSS, "onerror=", "Detects DOM event handler attribute injection"));
        r.add(new WafRule("XSS-205", "XSS - Event handler onload", WafCategory.XSS, "onload=", "Detects DOM onload event attribute injection"));
        r.add(new WafRule("XSS-206", "XSS - Event handler onclick", WafCategory.XSS, "onclick=", "Detects DOM onclick event attribute injection"));
        r.add(new WafRule("XSS-207", "XSS - IFrame injection", WafCategory.XSS, "<iframe", "Detects embedded iframe tag injection"));
        r.add(new WafRule("XSS-208", "XSS - Alert call", WafCategory.XSS, "alert(", "Detects popup modal execution probe"));
        r.add(new WafRule("XSS-209", "XSS - Document cookie access", WafCategory.XSS, "document.cookie", "Detects session hijacking cookie theft attempt"));

        // --- Path Traversal / LFI ---
        r.add(new WafRule("LFI-301", "Path Traversal - Dot dot slash", WafCategory.PATH_TRAVERSAL, "../", "Detects directory traversal parent navigation"));
        r.add(new WafRule("LFI-302", "Path Traversal - Dot dot backslash", WafCategory.PATH_TRAVERSAL, "..\\", "Detects Windows-style path traversal"));
        r.add(new WafRule("LFI-303", "Path Traversal - URL encoded slash", WafCategory.PATH_TRAVERSAL, "..%2f", "Detects percent-encoded directory traversal"));
        r.add(new WafRule("LFI-304", "Path Traversal - URL encoded dots", WafCategory.PATH_TRAVERSAL, "%2e%2e", "Detects double dot percent encoding"));
        r.add(new WafRule("LFI-305", "Path Traversal - /etc/passwd disclosure", WafCategory.PATH_TRAVERSAL, "etc/passwd", "Detects POSIX credential file disclosure attempt"));
        r.add(new WafRule("LFI-306", "Path Traversal - /etc/shadow disclosure", WafCategory.PATH_TRAVERSAL, "etc/shadow", "Detects POSIX password shadow disclosure attempt"));
        r.add(new WafRule("LFI-307", "Path Traversal - Windows win.ini disclosure", WafCategory.PATH_TRAVERSAL, "win.ini", "Detects Windows system configuration access"));

        // --- Remote Command Execution (RCE) ---
        r.add(new WafRule("RCE-401", "RCE - Bash pipe execution", WafCategory.RCE, "| bash", "Detects piped bash execution"));
        r.add(new WafRule("RCE-402", "RCE - Sh pipe execution", WafCategory.RCE, "| sh", "Detects piped shell execution"));
        r.add(new WafRule("RCE-403", "RCE - Cat passwd command", WafCategory.RCE, "; cat /", "Detects command chained file read"));
        r.add(new WafRule("RCE-404", "RCE - Wget downloader", WafCategory.RCE, "; wget ", "Detects command chained remote payload download"));
        r.add(new WafRule("RCE-405", "RCE - Curl downloader", WafCategory.RCE, "; curl ", "Detects command chained curl transfer"));
        r.add(new WafRule("RCE-406", "RCE - Command substitution", WafCategory.RCE, "$(", "Detects subshell command evaluation"));
        r.add(new WafRule("RCE-407", "RCE - Chained whoami", WafCategory.RCE, "&& whoami", "Detects privilege discovery command"));

        DEFAULT_RULES = Collections.unmodifiableList(r);
    }

    private CoreWafRuleSet() {}

    public static List<WafRule> defaultRules() {
        return DEFAULT_RULES;
    }
}
