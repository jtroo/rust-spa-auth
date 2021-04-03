<template>
  <v-col justify="center" cols="3">
    <v-form ref="loginForm" v-on:submit.prevent="authenticate">
      <v-text-field
        label="Email"
        :rules="rules"
        v-model="email"
        hide-details="auto"
      ></v-text-field>
      <v-text-field
        label="Password"
        :rules="rules"
        :append-icon="showPw ? 'mdi-eye' : 'mdi-eye-off'"
        :type="showPw ? 'text' : 'password'"
        v-model="pw"
        @click:append="showPw = !showPw"
      ></v-text-field>
      <v-col align="right">
        <div
          class="mt-5 float-left red--text capitalize"
        >
          {{error}}
        </div>
        <v-btn
          type="submit"
          value="Submit"
          class="mt-3"
          color="primary"
          justify="right"
          :loading="isReqWaiting"
        >
          Login
        </v-btn>
      </v-col>
    </v-form>
  </v-col>
</template>

<script>

import api from '@/api';

export default {
  name: 'HelloWorld',

  data() {
    return {
      email: '',
      pw: '',
      showPw: false,

      isReqWaiting: false,
      error: '',

      rules : [
        (v) => !!v || 'Required',
      ],
    }
  },

  methods: {
    authenticate() {
      if (!this.$refs.loginForm.validate()) {
        return;
      }

      this.isReqWaiting = true;
      api.login(this.email, this.pw)
        .then(() => this.$router.push('/home'))
        .catch((e) => { this.error = api.getErrorMsg(e); })
        .finally(() => { this.isReqWaiting = false; });
    },
  },

  created() {
    api.access()
      .then(() => this.$router.push('/home'))
      .catch(() => {});
  },
}

</script>
