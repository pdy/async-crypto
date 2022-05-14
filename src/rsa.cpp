#include "napi.h"

#define SO_IMPLEMENTATION
#include <simpleopenssl/simpleopenssl.h>

namespace {

namespace internal {
  struct OSSLFreeDeleter
  {
    void operator()(uint8_t *ptr) const
    {
      if(ptr)
        OPENSSL_free(ptr);
    }
  };
  
}

using ByteBuffer = std::unique_ptr<uint8_t[], internal::OSSLFreeDeleter>;

so::Bytes toSoBytes(const Napi::Buffer<uint8_t> &buff)
{
  so::Bytes ret; ret.reserve(buff.ByteLength());
  for(size_t i = 0; i < buff.ByteLength(); ++i)
    ret.push_back(buff[i]);

  return ret;
}

void byte_array_delete(Napi::Env /*env*/, uint8_t *arr, const char * /*hint*/ ) 
{
//   std::cout << "BYTE_ARRAY_DELETE " << hint << "\n";
  delete[] arr;
//  ByteBuffer tmp(arr);
}


void byte_array_ossl_free(Napi::Env /*env*/, uint8_t *arr, const char * /*hint*/ )
{
  OPENSSL_free(arr);
} 

namespace rsa {

class CreateKey : public Napi::AsyncWorker
{
  int m_keyBits;
  ByteBuffer m_privDer;
  size_t m_privSize; 
  ByteBuffer m_pubDer;
  size_t m_pubSize;

public:
  CreateKey(Napi::Function &cb, int keyBits)
    : AsyncWorker(cb), m_keyBits{keyBits}
  {}

  void Execute() override
  {
    static constexpr int ALLOWED_KEY_BYTES[] = {1024, 2048, 3072, 4096, 5120, 6144, 7168};
    if(!std::any_of(std::begin(ALLOWED_KEY_BYTES), std::end(ALLOWED_KEY_BYTES), [&](int val){ return val == m_keyBits; }))
    {
      AsyncWorker::SetError("Incorrect key bits value. Allowed values 1024, 2048, 3072, 4096, 5120, 6144, 7168");
      return;
    }

    auto key = so::rsa::create(static_cast<so::rsa::KeyBits>(m_keyBits), so::rsa::Exponent::_65537_);
    if(!key)
    {
      AsyncWorker::SetError(key.msg());
      return;
    }


    {
      uint8_t *ptr = nullptr; // this needs to be freed with OPENSSL_free
      const int len = i2d_RSAPrivateKey(key.value.get(), &ptr);
      if (0 > len)
      {
        AsyncWorker::SetError(so::getLastErrString());
        return;
      }

      m_privDer.reset(ptr);
      m_privSize = static_cast<size_t>(len);
    }

    {
      uint8_t *ptr = nullptr; // this needs to be freed with OPENSSL_free
      const int len = i2d_RSA_PUBKEY(key.value.get(), &ptr);
      if (0 > len)
      {
        AsyncWorker::SetError(so::getLastErrString());
        return;
      }

      m_pubDer.reset(ptr);
      m_pubSize = static_cast<size_t>(len);
    }

  }

  void OnOK() override
  {
    Napi::HandleScope scope(Env());

    Callback().Call({
      Env().Undefined(),
      Napi::Buffer<uint8_t>::New(
          Env(),
          m_privDer.release(),
          m_privSize,
          byte_array_ossl_free,
          "CreateKey priv key"     
      ),

      Napi::Buffer<uint8_t>::New(
          Env(),
          m_pubDer.release(),
          m_pubSize,
          byte_array_ossl_free,
          "CreateKey pub key"     
      )
    });
  }

};

class CreateKeyPem : public Napi::AsyncWorker
{
  int m_keyBits;
  std::string m_priv;
  std::string m_pub;

public:
  CreateKeyPem(Napi::Function &cb, int keyBits)
    : AsyncWorker(cb), m_keyBits{keyBits}
  {}

  void Execute() override
  {
    static constexpr int ALLOWED_KEY_BYTES[] = {1024, 2048, 3072, 4096, 5120, 6144, 7168};
    if(!std::any_of(std::begin(ALLOWED_KEY_BYTES), std::end(ALLOWED_KEY_BYTES), [&](int val){ return val == m_keyBits; }))
    {
      AsyncWorker::SetError("Incorrect key bits value. Allowed values 1024, 2048, 3072, 4096, 5120, 6144, 7168");
      return;
    }

    auto key = so::rsa::create(static_cast<so::rsa::KeyBits>(m_keyBits), so::rsa::Exponent::_65537_);
    if(!key)
    {
      AsyncWorker::SetError(key.msg());
      return;
    }

    auto priv = so::rsa::convertPrivKeyToPem(*key.value);
    if(!priv)
    {
      AsyncWorker::SetError(priv.msg());
      return;
    }

    auto pub = so::rsa::convertPubKeyToPem(*key.value);
    if(!pub)
    {
      AsyncWorker::SetError(pub.msg());
      return;
    }

    m_priv = priv.moveValue();
    m_pub= pub.moveValue();
  }

  void OnOK() override
  {
    Napi::HandleScope scope(Env());

    Callback().Call({
      Env().Undefined(),
      Napi::String::New(Env(), m_priv), 
      Napi::String::New(Env(), m_pub)
    });
  }

};

class PemPrivKeyToDerAsync : public Napi::AsyncWorker
{
  std::string m_pem;
  std::unique_ptr<uint8_t[]> m_outDer;
  size_t m_size;

public:
  PemPrivKeyToDerAsync(Napi::Function &callback, std::string &&pem)
    : AsyncWorker(callback), m_pem{std::move(pem)}, m_outDer{nullptr}
  {}

  void Execute() override
  {
    const auto result = so::rsa::convertPemToPrivKey(m_pem);
    if(!result)
      AsyncWorker::SetError(result.msg());
    else
    {
      const auto der = so::rsa::convertPrivKeyToDer(*result.value);
      if(!der)
        AsyncWorker::SetError(der.msg());
      else
      {
        m_outDer = std::make_unique<uint8_t[]>(der.value.size());
        for(size_t i = 0; i < der.value.size(); ++i)
          m_outDer[i] = der.value[i];

        m_size = der.value.size();
      }
    }
  }

  void OnOK() override
  {
    Napi::HandleScope scope(Env()); 

    Callback().Call({
        Env().Undefined(),
        Napi::Buffer<uint8_t>::New(
            Env(),
            m_outDer.release(),
            m_size,
            byte_array_delete,
            "PemPrivKeyToDerAsync")
    });
  }
};

class DerPrivToPemAsync : public Napi::AsyncWorker
{
  so::Bytes m_inDer;
  std::string m_pem;

public:
  DerPrivToPemAsync(Napi::Function &callback, so::Bytes &&der)
    : AsyncWorker(callback), m_inDer{std::move(der)} 
  {}

  void Execute() override
  {
    const auto result = so::rsa::convertDerToPrivKey(m_inDer);
    if(!result)
      AsyncWorker::SetError(result.msg());
    else
    {
      auto pem = so::rsa::convertPrivKeyToPem(*result.value);
      if(!pem)
        AsyncWorker::SetError(pem.msg());
      else
        m_pem = pem.moveValue();
    }
  }

  void OnOK() override
  {
    Napi::HandleScope scope(Env()); 

    Callback().Call({
        Env().Undefined(),
        Napi::String::New(Env(), m_pem) 
    });
  }
};

class PemPubToDerAsync : public Napi::AsyncWorker
{
  std::string m_pem;
  so::Bytes m_der;

public:
  PemPubToDerAsync(Napi::Function &cb, std::string &&pem)
    : AsyncWorker(cb), m_pem{std::move(pem)}
  {}

  void Execute() override
  {
    auto key = ::so::rsa::convertPemToPubKey(m_pem);
    if(!key)
      AsyncWorker::SetError(key.msg());
    else
    {
      auto der = ::so::rsa::convertPubKeyToDer(*key.value);
      if(!der)
        AsyncWorker::SetError(der.msg());
      else
        m_der = der.moveValue();
    }
  }

  void OnOK() override
  {
    Napi::HandleScope scope(Env());

    Callback().Call({
      Env().Undefined(),
      Napi::Buffer<uint8_t>::Copy(Env(), m_der.data(), m_der.size())
    });
  }
};

class DerPubToPemAsync : public Napi::AsyncWorker
{
  so::Bytes m_inDer;
  std::string m_pem;

public:
  DerPubToPemAsync(Napi::Function &callback, so::Bytes &&der)
    : AsyncWorker(callback), m_inDer{std::move(der)}
  {}

  void Execute() override
  {
    const auto result = so::rsa::convertDerToPubKey(m_inDer);
    if(!result)
      AsyncWorker::SetError(result.msg());
    else
    {
      auto pem = so::rsa::convertPubKeyToPem(*result.value);
      if(!pem)
        AsyncWorker::SetError(pem.msg());
      else
        m_pem = pem.moveValue();
    }
  }

  void OnOK() override
  {
    Napi::HandleScope scope(Env());

    Callback().Call({
        Env().Undefined(),
        Napi::String::New(Env(), m_pem)
    });
  }
};

using RsaSignFunction = decltype(&so::rsa::signSha1);
using RsaVerifyFunction = decltype(&so::rsa::verifySha1Signature);

class Sign : public Napi::AsyncWorker
{
  so::Bytes m_data;
  so::Bytes m_derKey;
  so::Bytes m_signature;
  RsaSignFunction m_func;

public:
  Sign(Napi::Function &callback, so::Bytes &&derData, so::Bytes &&derKey, RsaSignFunction func)
    : AsyncWorker(callback), m_data{std::move(derData)}, m_derKey{std::move(derKey)}, m_func{func}
  {}

  void Execute() override
  {
    auto key = so::rsa::convertDerToPrivKey(m_derKey);
    if(!key)
    {
      AsyncWorker::SetError(key.msg());
      return;
    }

    auto signature = m_func(m_data, *key.value);
    if(!signature)
      AsyncWorker::SetError(signature.msg());
    else
      m_signature = signature.moveValue();
  }

  void OnOK() override
  {
    Napi::HandleScope scope(Env());

    Callback().Call({
      Env().Undefined(),
      Napi::Buffer<uint8_t>::Copy(Env(), m_signature.data(), m_signature.size())
    });
  }
};

class Verify : public Napi::AsyncWorker
{
  so::Bytes m_signature;
  so::Bytes m_data;
  so::Bytes m_derKey;
  bool m_result{false};
  RsaVerifyFunction m_verify;

public:
  Verify(Napi::Function &callback, so::Bytes signature, so::Bytes data, so::Bytes derKey, RsaVerifyFunction verify)
    : AsyncWorker(callback), m_signature{std::move(signature)}, m_data{std::move(data)}, m_derKey{std::move(derKey)}, m_verify{verify}
  {}

  void Execute() override
  {
    auto key = so::rsa::convertDerToPubKey(m_derKey);
    if(!key)
    {
      AsyncWorker::SetError(key.msg());
      return;
    }

    auto verify = m_verify(m_signature, m_data, *key.value);
    if(!verify)
      AsyncWorker::SetError(verify.msg());
    else
      m_result = verify.value;
  }

  void OnOK() override
  {
    Napi::HandleScope scope(Env());

    Callback().Call({
      Env().Undefined(),
      Napi::Boolean::New(Env(), m_result)
    });
  }
};

namespace internal {

void SignTemplate(const Napi::CallbackInfo &info, rsa::RsaSignFunction signFunc)
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

void VerifyTemplate(const Napi::CallbackInfo &info, rsa::RsaVerifyFunction verifyFunc)
{
  if(!info[0].IsBuffer())
  {
    Napi::Error::New(info.Env(), "rsa::verify: signature not a buffer").ThrowAsJavaScriptException();
    return;
  }

  if(!info[1].IsBuffer())
  {
    Napi::Error::New(info.Env(), "rsa::verify: data not a buffer").ThrowAsJavaScriptException();
    return;
  }

  if(!info[2].IsBuffer())
  {
    Napi::Error::New(info.Env(), "rsa::verify: derKey not a buffer").ThrowAsJavaScriptException();
    return;
  }

  if(!info[3].IsFunction())
  {
    Napi::Error::New(info.Env(), "rsa::sign: callback not function").ThrowAsJavaScriptException();
    return;
  }

  auto sig = toSoBytes(info[0].As<Napi::Buffer<uint8_t>>());
  auto data = toSoBytes(info[1].As<Napi::Buffer<uint8_t>>());
  auto derKey = toSoBytes(info[2].As<Napi::Buffer<uint8_t>>());
  auto callback = info[3].As<Napi::Function>();
  
  auto *async = new rsa::Verify(callback, std::move(sig), std::move(data), std::move(derKey), verifyFunc);
  async->Queue();
}

} // internal

void createKey(const Napi::CallbackInfo &info)
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

void createKeyPEM(const Napi::CallbackInfo &info)
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

  auto *async = new ::rsa::CreateKeyPem(cb, keyBits);
  async->Queue();
}

void pemPrivKeyToDer(const Napi::CallbackInfo &info)
{
  if(!info[0].IsString())
  {
    Napi::Error::New(info.Env(), "rsa::pemPrivKeyToDer: pemPriv not a string").ThrowAsJavaScriptException();
    return;
  }
  
  if(!info[1].IsFunction())
  {
    Napi::Error::New(info.Env(), "rsa::pemPrivKeyToDer: callback not a function").ThrowAsJavaScriptException();
    return;
  }

  std::string pemPriv = info[0].As<Napi::String>();
  Napi::Function callback = info[1].As<Napi::Function>();

  auto *async = new rsa::PemPrivKeyToDerAsync(callback, std::move(pemPriv));
  async->Queue();
}

void derPrivKeyToPem(const Napi::CallbackInfo &info)
{
  if(!info[0].IsBuffer())
  {
    Napi::Error::New(info.Env(), "rsa::derPrivKeyToPem: derPriv not a string").ThrowAsJavaScriptException();
    return;
  }
  
  if(!info[1].IsFunction())
  {
    Napi::Error::New(info.Env(), "rsa::derPrivKeyToPem: callback not a function").ThrowAsJavaScriptException();
    return;
  }

  auto der = toSoBytes(info[0].As<Napi::Buffer<uint8_t>>());
  auto callback = info[1].As<Napi::Function>();

  auto *async = new rsa::DerPrivToPemAsync(callback, std::move(der));
  async->Queue();
}

void pemPubKeyToDer(const Napi::CallbackInfo &info)
{
  if(!info[0].IsString())
  {
    Napi::Error::New(info.Env(), "rsa::pemPubKeyToDer: pemPub not a string").ThrowAsJavaScriptException();
    return;
  }
  
  if(!info[1].IsFunction())
  {
    Napi::Error::New(info.Env(), "rsa::pemPubKeyToDer: callback not a function").ThrowAsJavaScriptException();
    return;
  }

  std::string pemPub = info[0].As<Napi::String>();
  Napi::Function callback = info[1].As<Napi::Function>();

  auto *async = new rsa::PemPubToDerAsync(callback, std::move(pemPub));
  async->Queue();
} 

void derPubKeyToPem(const Napi::CallbackInfo &info)
{
  if(!info[0].IsBuffer())
  {
    Napi::Error::New(info.Env(), "rsa::derPubKeyToPem: derPub not a string").ThrowAsJavaScriptException();
    return;
  }
  
  if(!info[1].IsFunction())
  {
    Napi::Error::New(info.Env(), "rsa::derPubKeyToPem: callback not a function").ThrowAsJavaScriptException();
    return;
  }

  auto der = toSoBytes(info[0].As<Napi::Buffer<uint8_t>>());
  auto callback = info[1].As<Napi::Function>();

  auto *async = new rsa::DerPubToPemAsync(callback, std::move(der));
  async->Queue();
}

void signSHA256(const Napi::CallbackInfo &info)
{
  internal::SignTemplate(info, so::rsa::signSha256); 
}

void verifySHA256(const Napi::CallbackInfo &info)
{
  internal::VerifyTemplate(info, so::rsa::verifySha256Signature); 
}

} // namespace rsa {

} // namespace
