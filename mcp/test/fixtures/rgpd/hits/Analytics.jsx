// Next.js components loading trackers with no consent check. Every `BUG`
// fires its rule exactly once.
import Script from 'next/script';
import { GoogleAnalytics } from '@next/third-parties/google';

const GA_ID = 'G-DDDD4444';

export function Analytics() {
  return (
    <>
      {/* BUG rgpd-tracker-ga4-without-consent */}
      <Script src={`https://www.googletagmanager.com/gtag/js?id=${GA_ID}`} strategy="afterInteractive" />
      {/* BUG rgpd-tracker-ga4-without-consent: @next/third-parties */}
      <GoogleAnalytics gaId={GA_ID} />
      {/* BUG rgpd-tracker-ga4-without-consent: a condition, but not a consent one */}
      {process.env.NODE_ENV === 'production' && <Script src="https://www.googletagmanager.com/gtag/js?id=G-EEEE5555" />}
    </>
  );
}

export function Video({ id }) {
  // BUG rgpd-youtube-embed-without-nocookie
  return <iframe width="560" height="315" src={`https://www.youtube.com/embed/${id}`} title="Video" />;
}
