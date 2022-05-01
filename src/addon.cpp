#include <napi.h>
#include <vector>
#include <memory>
#include <optional>

#include "async_workers.cpp"

namespace internal {

so::Bytes toSoBytes(const Napi::Buffer<uint8_t> &buff)
{
  so::Bytes ret; ret.reserve(buff.ByteLength());
  for(size_t i = 0; i < buff.ByteLength(); ++i)
    ret.push_back(buff[i]);

  return ret;
}

void RSA_Sign(const Napi::CallbackInfo &info, rsa::RsaSignFunction signFunc)
{
  if(!info[0].IsBuffer())
  {
    Napi::Error::New(info.Env(), "rsa::sign: data not a buffer").ThrowAsJavaScriptException();
    return;
  }

  if(!info[1].IsBuffer())
  {
    Napi::Error::New(info.Env(), "rsa::sign: derKey not a buffer").ThrowAsJavaScriptException();
    return;
  }

  if(!info[2].IsFunction())
  {
    Napi::Error::New(info.Env(), "rsa::sign: callback not function").ThrowAsJavaScriptException();
    return;
  }

  auto data = toSoBytes(info[0].As<Napi::Buffer<uint8_t>>());
  auto derKey = toSoBytes(info[1].As<Napi::Buffer<uint8_t>>());
  auto callback = info[2].As<Napi::Function>();

  auto *async = new rsa::Sign(callback, std::move(data), std::move(derKey), signFunc);
  async->Queue();
}

void RSA_Verify(const Napi::CallbackInfo &info, rsa::RsaVerifyFunction verify)
{
  auto sig = toSoBytes(info[0].As<Napi::Buffer<uint8_t>>());
  auto data = toSoBytes(info[1].As<Napi::Buffer<uint8_t>>());
  auto derKey = toSoBytes(info[2].As<Napi::Buffer<uint8_t>>());
  auto callback = info[3].As<Napi::Function>();
  
  auto *async = new rsa::Verify(callback, std::move(sig), std::move(data), std::move(derKey), verify);
  async->Queue();
}

} // internal


void InitOSSL(const Napi::CallbackInfo &/*info*/)
{
  so::init();
}

void CleanupOSSL(const Napi::CallbackInfo &/*info*/)
{
  so::cleanUp();
}

void RSA_CreateKey(const Napi::CallbackInfo &info)
{ 
  if(!info[0].IsNumber())
  {
    Napi::Error::New(info.Env(), "rsa::createKey: keyBits not a number").ThrowAsJavaScriptException();
    return;
  }
  
  if(!info[1].IsFunction())
  {
    Napi::Error::New(info.Env(), "rsa::createKey: callback not a function").ThrowAsJavaScriptException();
    return;
  }
  
  const int keyBits = info[0].As<Napi::Number>();
  auto cb = info[1].As<Napi::Function>();

  auto *async = new ::rsa::CreateKey(cb, keyBits);
  async->Queue();
}

void RSA_PemPrivKeyToDer(const Napi::CallbackInfo &info)
{
  std::string pemPriv = info[0].As<Napi::String>();
  Napi::Function callback = info[1].As<Napi::Function>();

  auto *async = new rsa::PemPrivKeyToDerAsync(callback, std::move(pemPriv));
  async->Queue();
}

void RSA_DerPrivKeyToPem(const Napi::CallbackInfo &info)
{
  const auto byteBuffer = info[0].As<Napi::Buffer<uint8_t>>();
  auto callback = info[1].As<Napi::Function>();

  so::Bytes der; der.reserve(byteBuffer.ByteLength());
  for(size_t i = 0; i < byteBuffer.ByteLength(); ++i)
    der.push_back(byteBuffer[i]);
  
  auto *async = new rsa::DerPrivToPemAsync(callback, std::move(der));
  async->Queue();
}
  
void RSA_SignSHA256(const Napi::CallbackInfo &info)
{
  internal::RSA_Sign(info, so::rsa::signSha256); 
}

void RSA_VerifySHA256(const Napi::CallbackInfo &info)
{
  internal::RSA_Verify(info, so::rsa::verifySha256Signature); 
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
  
  exports.Set(Napi::String::New(env, "rsa_createKey"), Napi::Function::New(env, RSA_CreateKey));
  exports.Set(Napi::String::New(env, "rsa_pemPrivKeyToDer"), Napi::Function::New(env, RSA_PemPrivKeyToDer));
  exports.Set(Napi::String::New(env, "rsa_derPrivKeyToPem"), Napi::Function::New(env, RSA_DerPrivKeyToPem));
  exports.Set(Napi::String::New(env, "rsa_signSHA256"), Napi::Function::New(env, RSA_SignSHA256));
  exports.Set(Napi::String::New(env, "rsa_verifySHA256"), Napi::Function::New(env, RSA_VerifySHA256));

  return exports;
};

NODE_API_MODULE(hello_world, init);
