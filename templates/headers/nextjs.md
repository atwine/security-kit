# Safe default security headers for a Next.js site

Two parts:

1. **Fixed headers**: the same on every response. Set them in
   `next.config.ts` with `headers()`:

   ```ts
   const securityHeaders = [
     { key: "X-Frame-Options", value: "DENY" },
     { key: "X-Content-Type-Options", value: "nosniff" },
     { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
     { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
     { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },
     { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
   ];

   const nextConfig = {
     poweredByHeader: false, // don't announce "X-Powered-By: Next.js"
     async headers() {
       return [{ source: "/:path*", headers: securityHeaders }];
     },
   };
   export default nextConfig;
   ```

2. **Content-Security-Policy**: the header that decides which scripts may
   run. A strict policy gives every page view a fresh random value (a
   "nonce") and allows only scripts carrying it. In Next.js this is built
   per request in the request handler (`proxy.ts` from Next.js 16,
   `middleware.ts` before). Follow the official guide for your Next.js
   version (`node_modules/next/dist/docs/`, "Content Security Policy"), and
   list only the outside addresses the site really uses, such as its
   sign-in service.

   Ship it in two steps. First use `Content-Security-Policy-Report-Only`,
   which warns in the browser console but blocks nothing. Visit every page,
   fix the warnings, then switch to `Content-Security-Policy`. Mozilla's
   Observatory only gives credit for the second.

   The kit's website scan fails while only the Report-Only header is sent
   (ZAP rule 10038), and that's expected: keep the warn-only step short,
   on a branch. Don't add a `10038 IGNORE` line to the scan's rules file to
   make it pass, because it would then stay silent after the switch too.

The kit's website scan (`site-scan.yml`) fails when the
Content-Security-Policy, anti-clickjacking or X-Content-Type-Options header
is missing.
