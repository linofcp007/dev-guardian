// Next.js components that render trackers only once consent is given.
// NOTHING here may fire (the JSX consent-condition guard: an element or a
// fragment after `consent && ` or `consent ? `).
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
      {consent.analytics && (
        <>
          <Script src="https://www.googletagmanager.com/gtag/js?id=G-MMMM3333" />
          <Script id="hotjar" strategy="afterInteractive">
            {`(function(h,o,t,j,a,r){
              h.hj=h.hj||function(){(h.hj.q=h.hj.q||[]).push(arguments)};
              h._hjSettings={hjid:7654321,hjsv:6};
              a=o.getElementsByTagName('head')[0];
              r=o.createElement('script');r.async=1;
              r.src=t+h._hjSettings.hjid+j+h._hjSettings.hjsv;
              a.appendChild(r);
            })(window,document,'https://static.hotjar.com/c/hotjar-','.js?sv=');`}
          </Script>
        </>
      )}
      {consent.marketing && (
        <Script id="meta-pixel">{`fbq('init', '555555555555555'); fbq('track', 'PageView');`}</Script>
      )}
    </>
  );
}

export function Video({ id }) {
  const consent = useConsent();
  return (
    <>
      {consent.marketing && <iframe src={`https://www.youtube.com/embed/${id}`} title="Video" />}
      {consent.marketing && (
        <div className="video">
          <iframe src={`https://www.youtube.com/embed/${id}?autoplay=0`} title="Video" />
        </div>
      )}
      <iframe src={`https://www.youtube-nocookie.com/embed/${id}`} title="Video" />
    </>
  );
}
