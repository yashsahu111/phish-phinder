import { createFileRoute } from "@tanstack/react-router";

import { RELEASE, releaseFingerprint } from "@/lib/release";

/**
 * Public deployment health check.
 *
 * GET /api/public/health
 *
 * Returns the release identity compiled into the bundle that is actually
 * serving the request. Compare `fingerprint` against the accepted release to
 * confirm a live host (Vercel, Lovable, anywhere) is running the approved build.
 *
 * Read-only: exposes no secrets, no user data, no request details.
 */
export const Route = createFileRoute("/api/public/health")({
  server: {
    handlers: {
      GET: () => {
        const body = {
          status: "ok" as const,
          app: RELEASE.app,
          version: RELEASE.version,
          channel: RELEASE.channel,
          baseline: RELEASE.baseline,
          releasedAt: RELEASE.releasedAt,
          note: RELEASE.note,
          fingerprint: releaseFingerprint(),
          checkedAt: new Date().toISOString(),
        };

        return new Response(JSON.stringify(body, null, 2), {
          status: 200,
          headers: {
            "content-type": "application/json; charset=utf-8",
            // Always answer from the live deployment, never from a CDN copy.
            "cache-control": "no-store, max-age=0",
          },
        });
      },
    },
  },
});
