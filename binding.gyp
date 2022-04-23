{
  "targets": [
    { 
      "cflags": [ "-fno-exceptions"],
      "include_dirs" : [
        "<!@(node -p \"require('node-addon-api').include\")",
        "./src/simpleopenssl/include"
      ],
      "target_name": "async-crypto",
      "sources": [
        "./src/addon.cpp",
      ],
      'defines': [ 'NAPI_DISABLE_CPP_EXCEPTIONS' ]
    }
  ]
}
