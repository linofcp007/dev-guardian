<!-- A Vue component that renders the embed only once consented. NOTHING here
     may fire (the template-condition guard, Vue `v-if` form: on a wrapper,
     and on the iframe itself). -->
<template>
  <div class="video">
    <template v-if="consent.marketing">
      <iframe src="https://www.youtube.com/embed/apresentacao"></iframe>
    </template>
    <iframe v-if="consentimento.marketing" src="https://www.youtube.com/embed/segundo"></iframe>
    <!-- Self-closing, and LAST: no `</iframe>` follows it, so only the
         self-closing form of the guard can reach it. -->
    <iframe v-if="consent.marketing" src="https://www.youtube.com/embed/terceiro" />
  </div>
</template>

<script>
export default {
  props: { consent: Object, consentimento: Object },
};
</script>
