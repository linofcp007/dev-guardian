// A component spec (`*.spec.jsx`, in the tracker rules' `paths.exclude`).
// Nothing here may fire.

import { render } from '@testing-library/react';
import { Consentimento } from './Consentimento';

it('nao inicia o pixel antes da escolha', () => {
  render(<Consentimento />);
  expect(document.body.innerHTML).not.toContain("fbq('init', '111111111111111');");
});
