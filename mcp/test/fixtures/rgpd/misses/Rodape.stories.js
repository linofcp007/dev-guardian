// A Storybook story (`*.stories.js`, in the tracker rules' `paths.exclude`):
// a demo for the people building the UI. Nothing here may fire.

import { Rodape } from './Rodape';

export default { title: 'Layout/Rodape', component: Rodape };

export const ComAnalitica = {
  args: { cabecalho: '<script async src="https://www.googletagmanager.com/gtag/js?id=G-DEMO"></script>' },
};
