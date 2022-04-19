'use strict'

const rsa = require('../index.js').rsa;

rsa.pemPrivKeyToDer("some string", function(err, ret) {
  if(err)
    console.log(err)

});
