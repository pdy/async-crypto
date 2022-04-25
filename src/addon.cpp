#include <napi.h>
#include <vector>
#include <memory>

#include "async_workers.cpp"

void InitOSSL(const Napi::CallbackInfo &/*info*/)
{
  so::init();
}

void CleanupOSSL(const Napi::CallbackInfo &/*info*/)
{
  so::cleanUp();
}

void ReverseByteBuffer(const Napi::CallbackInfo &info)
{
  auto byteBuffer = info[0].As<Napi::Buffer<uint8_t>>();
  Napi::Function callback = info[1].As<Napi::Function>(); 

  auto buffer = std::make_unique<uint8_t[]>(byteBuffer.ByteLength());
  for(size_t i = 0; i < byteBuffer.ByteLength(); ++i)
  {
    buffer[i] = byteBuffer[i];
  }

  auto *async = new BufferReverseAsync(callback, std::move(buffer), byteBuffer.ByteLength());
  async->Queue();
}

void RSA_CreateKey(const Napi::CallbackInfo &info)
{
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
  const auto dataBuffer = info[0].As<Napi::Buffer<uint8_t>>();
  const auto derKeyBuffer = info[1].As<Napi::Buffer<uint8_t>>();
  auto callback = info[2].As<Napi::Function>();

  so::Bytes data; data.reserve(dataBuffer.ByteLength());
  for(size_t i = 0; i < dataBuffer.ByteLength(); ++i)
    data.push_back(dataBuffer[i]);

  so::Bytes derKey; derKey.reserve(derKeyBuffer.ByteLength());
  for(size_t i = 0; i < derKeyBuffer.ByteLength(); ++i)
    derKey.push_back(derKeyBuffer[i]);

  auto *async = new rsa::SignSHA256(callback, std::move(data), std::move(derKey));
  async->Queue();
}

void RSA_VerifySHA256(const Napi::CallbackInfo &info)
{
  const auto sigBuffer = info[0].As<Napi::Buffer<uint8_t>>();
  const auto dataBuffer = info[1].As<Napi::Buffer<uint8_t>>();
  const auto derKeyBuffer = info[2].As<Napi::Buffer<uint8_t>>();
  auto callback = info[3].As<Napi::Function>();
  
  so::Bytes sig; sig.reserve(sigBuffer.ByteLength());
  for(size_t i = 0; i < sigBuffer.ByteLength(); ++i)
    sig.push_back(sigBuffer[i]);
  
  so::Bytes data; data.reserve(dataBuffer.ByteLength());
  for(size_t i = 0; i < dataBuffer.ByteLength(); ++i)
    data.push_back(dataBuffer[i]);

  so::Bytes derKey; derKey.reserve(derKeyBuffer.ByteLength());
  for(size_t i = 0; i < derKeyBuffer.ByteLength(); ++i)
    derKey.push_back(derKeyBuffer[i]);

  auto *async = new rsa::VerifySHA256(callback, std::move(sig), std::move(data), std::move(derKey));
  async->Queue();
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
  
  exports.Set(Napi::String::New(env, "reverseByteBuffer"), Napi::Function::New(env, ReverseByteBuffer));
  
  exports.Set(Napi::String::New(env, "rsa_createKey"), Napi::Function::New(env, RSA_CreateKey));
  exports.Set(Napi::String::New(env, "rsa_pemPrivKeyToDer"), Napi::Function::New(env, RSA_PemPrivKeyToDer));
  exports.Set(Napi::String::New(env, "rsa_derPrivKeyToPem"), Napi::Function::New(env, RSA_DerPrivKeyToPem));
  exports.Set(Napi::String::New(env, "rsa_signSHA256"), Napi::Function::New(env, RSA_SignSHA256));
  exports.Set(Napi::String::New(env, "rsa_verifySHA256"), Napi::Function::New(env, RSA_VerifySHA256));

  return exports;
};

NODE_API_MODULE(hello_world, init);
