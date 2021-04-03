<template>
  <v-app id="app">
    <v-app-bar app color="primary" justify="space-around" dark>
      <v-toolbar-title>Rust SPA Auth</v-toolbar-title>
      <v-spacer/>
      <v-btn v-on:click="logout()" v-if="!isOnLoginPg">
        Logout
      </v-btn>
    </v-app-bar>

    <v-container fill-height fluid class="x-ctn">
      <v-row>
        <v-col align="center" cols="12">
          <router-view/>
        </v-col>
      </v-row>
    </v-container>
  </v-app>
</template>

<style lang="scss">
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
}

#nav {
  padding: 30px;

  a {
    font-weight: bold;
    color: #2c3e50;

    &.router-link-exact-active {
      color: #42b983;
    }
  }
}
</style>

<script>

import api from '@/api';

export default {
  name: 'App',

  methods: {
    async logout() {
      await api.logout();
      this.$router.push('/login');
    }
  },

  computed: {
    isOnLoginPg() {
      return this.$route.path === '/login';
    },
  },
}

</script>
