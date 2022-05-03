#include <napi.h>
#include <vector>
#include <memory>
#include <optional>

#include "rsa.cpp"

void InitOSSL(const Napi::CallbackInfo &/*info*/)
{
  so::init();
}

void CleanupOSSL(const Napi::CallbackInfo &/*info*/)
{
  so::cleanUp();
}

Napi::String GetOpenSSLVersion(const Napi::CallbackInfo &info)
{
  return Napi::String::New(info.Env(), ::so::getOpenSSLVersion());
}

Napi::Object init(Napi::Env env, Napi::Object exports)
{
  exports.Set(Napi::String::New(env, "init"), Napi::Function::New(env, InitOSSL));
  exports.Set(Napi::String::New(env, "cleanup"), Napi::Function::New(env, CleanupOSSL));

  exports.Set(Napi::String::New(env, "getOpenSSLVersion"), Napi::Function::New(env, GetOpenSSLVersion));
  
  exports.Set(Napi::String::New(env, "rsa_createKey"), Napi::Function::New(env, ::rsa::createKey));
  exports.Set(Napi::String::New(env, "rsa_pemPrivKeyToDer"), Napi::Function::New(env, ::rsa::pemPrivKeyToDer));
  exports.Set(Napi::String::New(env, "rsa_derPrivKeyToPem"), Napi::Function::New(env, ::rsa::derPrivKeyToPem));
  exports.Set(Napi::String::New(env, "rsa_signSHA256"), Napi::Function::New(env, ::rsa::signSHA256));
  exports.Set(Napi::String::New(env, "rsa_verifySHA256"), Napi::Function::New(env, ::rsa::verifySHA256));

  return exports;
};

NODE_API_MODULE(hello_world, init);
