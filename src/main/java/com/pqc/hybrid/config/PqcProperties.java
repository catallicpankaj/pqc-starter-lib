package com.pqc.hybrid.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for PqcStarterLib.
 *
 * application.yml example:
 *
 *   spring:
 *     pqc:
 *       enabled: true
 *       preferred-mode: HYBRID
 *       allow-classical-fallback: true
 */
@ConfigurationProperties(prefix = "pqc")
public class PqcProperties {

    /** Master on/off switch */
    private boolean enabled = true;

    /** Preferred mode: HYBRID | PQC_ONLY | CLASSICAL */
    private String preferredMode = "HYBRID";

    /** Allow classical fallback for legacy clients */
    private boolean allowClassicalFallback = true;

    /** Max sessions to hold in memory */
    private int sessionCacheSize = 10000;

    public boolean isEnabled()                       { return enabled; }
    public void    setEnabled(boolean v)             { enabled = v; }
    public String  getPreferredMode()                { return preferredMode; }
    public void    setPreferredMode(String v)        { preferredMode = v; }
    public boolean isAllowClassicalFallback()        { return allowClassicalFallback; }
    public void    setAllowClassicalFallback(boolean v) { allowClassicalFallback = v; }
    public int     getSessionCacheSize()             { return sessionCacheSize; }
    public void    setSessionCacheSize(int v)        { sessionCacheSize = v; }
}
