import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

export interface IpGeo {
  ip: string;
  country: string;
  city: string;
  isp: string;
  org: string;
  lat: number;
  lon: number;
}

/**
 * Real-time IP geolocation via ip-api.com. Fetched server-side so the
 * HTTPS page never makes a mixed-content HTTP request from the browser.
 */
export const lookupIpGeo = createServerFn({ method: "GET" })
  .inputValidator((data) => z.object({ ip: z.string() }).parse(data))
  .handler(async ({ data }): Promise<IpGeo | null> => {
    try {
      const res = await fetch(
        `http://ip-api.com/json/${encodeURIComponent(data.ip)}?fields=status,query,country,city,isp,org,lat,lon`,
      );
      const json = (await res.json()) as {
        status?: string;
        query?: string;
        country?: string;
        city?: string;
        isp?: string;
        org?: string;
        lat?: number;
        lon?: number;
      };
      if (json.status !== "success") return null;
      return {
        ip: json.query ?? data.ip,
        country: json.country ?? "Unknown",
        city: json.city ?? "Unknown",
        isp: json.isp ?? "Unknown",
        org: json.org ?? json.isp ?? "Unknown",
        lat: json.lat ?? 0,
        lon: json.lon ?? 0,
      };
    } catch {
      return null;
    }
  });
