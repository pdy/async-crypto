'use strict';

const addon = require('../build/Release/hello_addon.node')

/**
 * @param {Buffer} buffer
 * @param {function} callback
 */
function reverseByteBuffer(buffer, callback) {
  return addon.reverseByteBuffer(buffer, callback);
}

module.exports = {
  reverseByteBuffer: reverseByteBuffer,
};



