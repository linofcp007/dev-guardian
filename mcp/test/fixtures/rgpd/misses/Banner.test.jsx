// A component test (`*.test.jsx`, in the tracker rules' `paths.exclude`):
// the Hotjar loader URL is an expected value, never served. Nothing here may
// fire.

import { render } from '@testing-library/react';
import { Banner } from './Banner';

test('so carrega o Hotjar depois de aceitar', () => {
  const { container } = render(<Banner aceite />);
  expect(container.innerHTML).toContain('<script src="https://static.hotjar.com/c/hotjar-0000000.js?sv=6"></script>');
});
