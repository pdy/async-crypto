{
  "targets": [
    { 
      "cflags": [ "-fno-exceptions", "-fPIC" ],
      "ldflags":[
        "-L./src/openssl_build/lib -Bstatic -lssl -lcrypto -Bdynamic -pthread -ldl"

      ],
      "include_dirs" : [
        "<!@(node -p \"require('node-addon-api').include\")",
        "./src/openssl_build/include",
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
