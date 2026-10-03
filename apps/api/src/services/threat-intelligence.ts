import { config } from "../config";

export interface ThreatResult {
  provider: string;
  isDemo: boolean;
  verdict: "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN";
  confidence: number;
  details: Record<string, unknown>;
}

export interface ThreatIntelligenceProvider {
  lookupIp(ipAddress: string): Promise<ThreatResult>;
}

export class DemoThreatProvider implements ThreatIntelligenceProvider {
  async lookupIp(ipAddress: string): Promise<ThreatResult> {
    const suspicious = ipAddress.startsWith("203.0.113.") || ipAddress.startsWith("198.51.100.");
    return {
      provider: "SecureWatch Demo Intelligence",
      isDemo: true,
      verdict: suspicious ? "SUSPICIOUS" : "UNKNOWN",
      confidence: suspicious ? 72 : 20,
      details: {
        notice: "Synthetic demonstration result; not verified by an external reputation provider.",
        documentationRange: suspicious
      }
    };
  }
}

export class VirusTotalProvider implements ThreatIntelligenceProvider {
  async lookupIp(ipAddress: string): Promise<ThreatResult> {
    if (!config.VIRUSTOTAL_API_KEY) throw new Error("VirusTotal API key is not configured");
    const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ipAddress)}`, {
      headers: { "x-apikey": config.VIRUSTOTAL_API_KEY }
    });
    if (!response.ok) throw new Error(`VirusTotal request failed with ${response.status}`);
    const payload = await response.json() as { data?: { attributes?: { last_analysis_stats?: Record<string, number> } } };
    const stats = payload.data?.attributes?.last_analysis_stats ?? {};
    const malicious = stats.malicious ?? 0;
    return {
      provider: "VirusTotal", isDemo: false,
      verdict: malicious > 0 ? "MALICIOUS" : "CLEAN",
      confidence: Math.min(100, malicious * 10), details: { analysisStats: stats }
    };
  }
}

export class AbuseIpDbProvider implements ThreatIntelligenceProvider {
  async lookupIp(ipAddress: string): Promise<ThreatResult> {
    if (!config.ABUSEIPDB_API_KEY) throw new Error("AbuseIPDB API key is not configured");
    const url = new URL("https://api.abuseipdb.com/api/v2/check");
    url.searchParams.set("ipAddress", ipAddress);
    url.searchParams.set("maxAgeInDays", "90");
    const response = await fetch(url, { headers: { Key: config.ABUSEIPDB_API_KEY, Accept: "application/json" } });
    if (!response.ok) throw new Error(`AbuseIPDB request failed with ${response.status}`);
    const payload = await response.json() as { data?: { abuseConfidenceScore?: number; countryCode?: string; isp?: string } };
    const confidence = payload.data?.abuseConfidenceScore ?? 0;
    return {
      provider: "AbuseIPDB", isDemo: false,
      verdict: confidence >= 70 ? "MALICIOUS" : confidence >= 25 ? "SUSPICIOUS" : "CLEAN",
      confidence, details: payload.data ?? {}
    };
  }
}

export function getThreatProvider(): ThreatIntelligenceProvider {
  if (config.THREAT_PROVIDER === "virustotal" && config.VIRUSTOTAL_API_KEY) return new VirusTotalProvider();
  if (config.THREAT_PROVIDER === "abuseipdb" && config.ABUSEIPDB_API_KEY) return new AbuseIpDbProvider();
  return new DemoThreatProvider();
}
