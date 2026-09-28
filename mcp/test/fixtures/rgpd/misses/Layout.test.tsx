// A layout test (`*.test.tsx`, in the tracker rules' `paths.exclude`).
// Nothing here may fire.

import { render } from '@testing-library/react';
import { Layout } from './Layout';

it('renderiza o GA so em producao', () => {
  const esperado = '<script async src="https://www.googletagmanager.com/gtag/js?id=G-TESTE"></script>';
  expect(render(<Layout />).container.innerHTML).not.toContain(esperado);
});
