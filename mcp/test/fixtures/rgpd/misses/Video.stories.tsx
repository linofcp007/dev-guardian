// A Storybook story (`*.stories.tsx`, in the tracker rules' `paths.exclude`).
// Nothing here may fire.

import type { Meta } from '@storybook/react';
import { Video } from './Video';

const meta: Meta<typeof Video> = { title: 'Media/Video', component: Video };
export default meta;

export const Incorporado = {
  args: { html: '<iframe width="560" height="315" src="https://www.youtube.com/embed/demo987"></iframe>' },
};
