#include <napi.h>
#include <vector>

#include "async_workers.cpp"

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

void RSA_PemPrivKeyToDer(const Napi::CallbackInfo &info)
{
  std::string pemPriv = info[0].As<Napi::String>();
  Napi::Function callback = info[1].As<Napi::Function>();

  auto *async = new RSA_PemPrivKeyToDerAsync(callback, std::move(pemPriv));
  async->Queue();
}

Napi::Object init(Napi::Env env, Napi::Object exports)
{
    exports.Set(Napi::String::New(env, "reverseByteBuffer"), Napi::Function::New(env, ReverseByteBuffer));
    exports.Set(Napi::String::New(env, "rsa_pemPrivKeyToDer"), Napi::Function::New(env, RSA_PemPrivKeyToDer));

    return exports;
};

NODE_API_MODULE(hello_world, init);
