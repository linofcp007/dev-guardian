<!-- A Vue single-file component. Each `BUG` fires
     rgpd-youtube-embed-without-nocookie exactly once. -->
<template>
  <div class="video">
    <!-- BUG -->
    <iframe width="560" height="315" :title="titulo"
            src="https://youtube.com/embed/dQw4w9WgXcQ?rel=0"></iframe>
    <!-- BUG: a v-if, but not a consent one -->
    <template v-if="mostrarVideo">
      <iframe src="https://www.youtube.com/embed/apresentacao"></iframe>
    </template>
  </div>
</template>

<script>
export default {
  props: { titulo: { type: String, default: 'Video' }, mostrarVideo: Boolean },
};
</script>
