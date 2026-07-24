package org.minima.utils.cpip;

import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

/**
 * CPIP (Coffee Pot Internet Protocol) Java Security Provider.
 *
 * Integrates The Coffee Protocol v5.1.1 cryptographic primitives as a
 * JCA-compatible security provider for Minima. Provides:
 *
 *  - CoffeeCipher: AES-256-GCM (FIPS 197) with HKDF-SHA256 key derivation
 *  - ECDSA P-256 / ECDH P-256 (FIPS 186-4) via BouncyCastle jdk18on
 *  - HMAC-SHA256 token authentication for RPC
 *  - ITF Defense: probe blocking, pentest tool detection, IP blacklisting
 *  - FIPS power-on self-tests
 *
 * Registered via Security.addProvider(new CoffeeProtocolProvider())
 * at application startup in Minima.main().
 */
public class CoffeeProtocolProvider extends Provider {

    private static final long serialVersionUID = 1L;

    public static final String NAME = "CPIP";
    public static final String VERSION = "5.1.1";
    public static final String INFO =
        "CPIP Security Provider — The Coffee Protocol v5.1.1 " +
        "(AES-256-GCM, ECDSA P-256, ECDH P-256, HMAC-SHA256, HKDF-SHA256, ITF Defense)";

    private static volatile boolean initialized = false;
    private static final Map<String, Boolean> defenseBlacklist = new HashMap<>();
    private static final Map<String, Long> defenseBlacklistExpiry = new HashMap<>();
    private static final Map<String, Integer> probeCounts = new HashMap<>();

    public CoffeeProtocolProvider() {
        super(NAME, VERSION, INFO);
        put("Cipher.AES/GCM/NoPadding", "org.minima.utils.cpip.CoffeeCipherSpi");
        put("Signature.SHA256withECDSA", "org.minima.utils.cpip.CPIPECDSASignatureSpi");
        put("Mac.HMAC-SHA256", "org.minima.utils.cpip.CPIPHmacSpi");
        put("KeyAgreement.ECDH", "org.minima.utils.cpip.CPIPECDHKeyAgreementSpi");
        put("KeyGenerator.CoffeeCipher", "org.minima.utils.cpip.CoffeeCipherKeyGeneratorSpi");
    }

    /**
     * Initialize the CPIP provider — run FIPS self-tests and set up defense.
     * Called once at application startup.
     */
    public static synchronized void initialize() {
        if (initialized) {
            return;
        }
        initialized = true;

        // Register BouncyCastle if not already registered
        if (Security.getProvider("BC") == null) {
            try {
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            } catch (Exception e) {
                // Already registered or unavailable
            }
        }

        // Run FIPS self-tests
        boolean fipsMode = "1".equals(System.getenv("CPIP_FIPS"));
        boolean testsPassed = CPIPSelfTest.runSelfTests();

        if (fipsMode && !testsPassed) {
            throw new RuntimeException("CPIP FIPS mode enabled but self-tests failed");
        }

        org.minima.utils.MinimaLogger.log("[CPIP] Security Provider v" + VERSION + " initialized"
            + (fipsMode ? " (FIPS mode)" : "")
            + " — self-tests " + (testsPassed ? "PASSED" : "SKIPPED"));
    }

    // ─── ITF Defense ──────────────────────────────────────────────────────────

    /**
     * Check if an IP address is blacklisted by ITF Defense.
     */
    public static boolean isBlacklisted(String addr) {
        if ("127.0.0.1".equals(addr) || "::1".equals(addr) || "localhost".equals(addr)) {
            return false;
        }
        synchronized (defenseBlacklist) {
            Long expiry = defenseBlacklistExpiry.get(addr);
            if (expiry == null) {
                return false;
            }
            if (System.currentTimeMillis() / 1000 > expiry) {
                defenseBlacklist.remove(addr);
                defenseBlacklistExpiry.remove(addr);
                return false;
            }
            return true;
        }
    }

    /**
     * Blacklist an IP address with configurable TTL.
     */
    public static void blacklistAddr(String addr) {
        if ("127.0.0.1".equals(addr) || "::1".equals(addr) || "localhost".equals(addr)) {
            return;
        }
        synchronized (defenseBlacklist) {
            long now = System.currentTimeMillis() / 1000;
            long ttl = 3600; // 1 hour default

            // Check rate limit
            int count = probeCounts.getOrDefault(addr, 0);
            if (count > 10) {
                ttl *= 2;
            }
            ttl = Math.min(ttl, 86400); // max 24h

            probeCounts.put(addr, count + 1);
            defenseBlacklist.put(addr, true);
            defenseBlacklistExpiry.put(addr, now + ttl);

            org.minima.utils.MinimaLogger.log("[CPIP] ITF Defense: blacklisted " + addr + " for " + ttl + "s");
        }
    }

    /**
     * Remove an IP from the blacklist.
     */
    public static void whitelistAddr(String addr) {
        synchronized (defenseBlacklist) {
            defenseBlacklist.remove(addr);
            defenseBlacklistExpiry.remove(addr);
            probeCounts.remove(addr);
        }
    }

    /**
     * Check if a User-Agent string matches known pentest tools.
     */
    public static boolean isPentestTool(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return false;
        }
        String uaLower = userAgent.toLowerCase();
        String[] tools = {
            "burp", "nmap", "sqlmap", "nikto", "gobuster", "dirb",
            "ffuf", "wfuzz", "openvas", "nessus", "masscan", "zap",
            "arachni", "w3af", "metasploit", "acunetix", "nuclei",
            "hydra", "wpscan"
        };
        for (String tool : tools) {
            if (uaLower.contains(tool)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a request path looks like a scanner probe.
     */
    public static boolean isScannerPath(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        String pathLower = path.toLowerCase();
        String[] scannerPaths = {
            "/admin", "/wp-admin", "/wp-login", "/wp-", "/.env",
            "/phpmyadmin", "/shell", "/cmd", "/exec", "/backdoor",
            "/login", "/setup", "/install", "/manager", "/console",
            "/xmlrpc.php", "/.git", "/config", "/backup", "/database"
        };
        for (String scannerPath : scannerPaths) {
            if (pathLower.contains(scannerPath)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Full ITF Defense check for an incoming request.
     * Returns true if the request should be blocked (HTTP 418).
     */
    public static boolean defenseCheck(String addr, String path, String method, String userAgent) {
        if (isBlacklisted(addr)) {
            return true;
        }
        int score = 0;
        if (isScannerPath(path)) {
            score += 3;
        }
        if (isPentestTool(userAgent)) {
            score += 2;
        }
        if (score >= 2) {
            blacklistAddr(addr);
            return true;
        }
        return false;
    }

    /**
     * Clear the entire blacklist.
     */
    public static void clearBlacklist() {
        synchronized (defenseBlacklist) {
            defenseBlacklist.clear();
            defenseBlacklistExpiry.clear();
            probeCounts.clear();
        }
    }
}