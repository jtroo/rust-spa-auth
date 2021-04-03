<template>
  <v-col justify="center">
    <h1>
      This is a home page
    </h1>
    <v-row class="mt-4" justify="center">
      <v-btn v-on:click="clickUser()">
        I am a user
      </v-btn>
      <v-btn class="ml-6" v-on:click="clickAdmin()" v-if="isAdmin">
        I am an admin!
      </v-btn>
    </v-row>
    <v-row justify="center" class="mt-7">
      {{result}}
    </v-row>
  </v-col>
</template>

<script>

import api from '@/api';

export default {
  name: 'Home',

  data() {
    return {
      result: '',
      isAdmin: false,
    };
  },

  methods: {
    clickUser() {
      api.callUser().then((v) => { this.result =  `Hello ${v}`; });
    },

    clickAdmin() {
      api.callAdmin().then((v) => { this.result = `Hello ${v}`; });
    },
  },

  created() {
    api.access()
      .then(api.claims)
      .then((claims) => { this.isAdmin = claims.role === 'admin'; })
      .catch(() => this.$router.push('/login'));
  },
}

</script>
