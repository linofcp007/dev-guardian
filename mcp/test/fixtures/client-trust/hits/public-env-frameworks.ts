/**
 * client-public-env-secret across the other browser prefixes: Expo, Create
 * React App, Gatsby, Vue CLI, Nuxt.
 */

export const keys = {
  expo: process.env.EXPO_PUBLIC_REPLICATE_API_TOKEN, // BUG: client-public-env-secret -- Expo
  cra: process.env.REACT_APP_JWT_SECRET, // BUG: client-public-env-secret -- Create React App
  gatsby: process.env.GATSBY_ALGOLIA_ADMIN_KEY, // BUG: client-public-env-secret -- Gatsby, an admin key
  vue: process.env.VUE_APP_DB_PASSWORD, // BUG: client-public-env-secret -- Vue CLI
  nuxt: process.env.NUXT_PUBLIC_RESEND_API_KEY, // BUG: client-public-env-secret -- Nuxt
};
