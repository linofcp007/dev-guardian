<!-- A Vue single-file component. The single `BUG` fires
     rgpd-youtube-embed-without-nocookie exactly once. -->
<template>
  <div class="video">
    <!-- BUG -->
    <iframe width="560" height="315" :title="titulo"
            src="https://youtube.com/embed/dQw4w9WgXcQ?rel=0"></iframe>
  </div>
</template>

<script>
export default {
  props: { titulo: { type: String, default: 'Video' } },
};
</script>
