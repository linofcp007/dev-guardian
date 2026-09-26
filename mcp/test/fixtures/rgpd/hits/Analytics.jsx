// Next.js components loading trackers with no consent check. Every `BUG`
// fires its rule exactly once.
import Script from 'next/script';
import { GoogleAnalytics } from '@next/third-parties/google';

const GA_ID = 'G-DDDD4444';

export function Analytics({ consent }) {
  return (
    <>
      {/* BUG rgpd-tracker-ga4-without-consent */}
      <Script src={`https://www.googletagmanager.com/gtag/js?id=${GA_ID}`} strategy="afterInteractive" />
      {/* BUG rgpd-tracker-ga4-without-consent: @next/third-parties */}
      <GoogleAnalytics gaId={GA_ID} />
      {/* BUG rgpd-tracker-ga4-without-consent: a condition, but not a consent one */}
      {process.env.NODE_ENV === 'production' && <Script src="https://www.googletagmanager.com/gtag/js?id=G-EEEE5555" />}
      {/* BUG rgpd-tracker-ga4-without-consent: a NEGATED consent condition */}
      {!consent.analytics && (
        <>
          <Script src="https://www.googletagmanager.com/gtag/js?id=G-HHHH8888" />
        </>
      )}
      {/* BUG rgpd-tracker-ga4-without-consent: the ELSE branch of a consent ternary */}
      {consent.analytics ? null : <Script src="https://www.googletagmanager.com/gtag/js?id=G-IIII9999" />}
    </>
  );
}

export function Video({ id }) {
  // BUG rgpd-youtube-embed-without-nocookie
  return <iframe width="560" height="315" src={`https://www.youtube.com/embed/${id}`} title="Video" />;
}
