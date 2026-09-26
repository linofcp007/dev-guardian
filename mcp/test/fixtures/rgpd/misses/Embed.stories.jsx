// A Storybook story: demo content for the people building the UI, never
// served to the app's visitors. `*.stories.*` is in the tracker rules'
// `paths.exclude`. Nothing in this file may fire.

import { CartaoEmbed } from './CartaoEmbed';

export default { title: 'Cartoes/Embed', component: CartaoEmbed };

export const Video = {
  args: {
    html: '<iframe width="480" height="270" src="https://www.youtube.com/embed/exemplo123" allowfullscreen></iframe>',
  },
};
