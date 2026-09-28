// A component spec: `*.spec.tsx` is in the tracker rules' `paths.exclude`.
// Nothing in this file may fire.

import { render } from '@testing-library/react';
import { Pixel } from './Pixel';

it('inicia o pixel com o id configurado', () => {
  const fbq = vi.fn();
  render(<Pixel fbq={fbq} />);
  expect(fbq).toHaveBeenCalledWith('init', '000000000000000');
  const snippet = "fbq('init', '000000000000000');";
  expect(document.body.innerHTML).not.toContain(snippet);
});
