// A Next.js root layout written in plain .js (app/layout.js). The single BUG
// fires rgpd-tracker-ga4-without-consent exactly once.
import Script from 'next/script';

export default function RootLayout({ children }) {
  return (
    <html lang="pt-PT">
      <body>
        {children}
        {/* BUG */}
        <Script src="https://www.googletagmanager.com/gtag/js?id=G-KKKK1111" strategy="afterInteractive" />
      </body>
    </html>
  );
}
