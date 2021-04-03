import Vue from 'vue';
import Vuetify from 'vuetify/lib/framework';

import colours from 'vuetify/lib/util/colors';

Vue.use(Vuetify);

export default new Vuetify({
  theme: {
    themes: {
      light: {
        primary: colours.pink.lighten1,
        secondary: colours.purple,
        accent: colours.pink.darken2,
        error: colours.red.darken3,
      }
    }
  }
});
