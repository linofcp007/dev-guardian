// Next.js components that render trackers only once consent is given.
// NOTHING here may fire (the JSX consent-condition guard).
import Script from 'next/script';
import { GoogleAnalytics } from '@next/third-parties/google';
import { useConsent } from './consent';

export function Analytics() {
  const consent = useConsent();
  return (
    <>
      {consent.analytics && (
        <Script src="https://www.googletagmanager.com/gtag/js?id=G-DDDD4444" strategy="afterInteractive" />
      )}
      {consent.analytics ? <GoogleAnalytics gaId="G-DDDD4444" /> : null}
    </>
  );
}

export function Video({ id }) {
  const consent = useConsent();
  return (
    <>
      {consent.marketing && <iframe src={`https://www.youtube.com/embed/${id}`} title="Video" />}
      <iframe src={`https://www.youtube-nocookie.com/embed/${id}`} title="Video" />
    </>
  );
}
