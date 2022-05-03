#include "napi.h"
#include <iostream>
#include <memory>

#define SO_IMPLEMENTATION
#include <simpleopenssl/simpleopenssl.h>

namespace {

void byte_array_delete(Napi::Env /*env*/, uint8_t *arr, const char * /*hint*/ ) 
{
//   std::cout << "BYTE_ARRAY_DELETE " << hint << "\n";
  delete[] arr;
}

namespace rsa {

class CreateKey : public Napi::AsyncWorker
{
  int m_keyBits;
  so::Bytes m_privDer;
  so::Bytes m_pubDer;

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

    auto der = so::rsa::convertPrivKeyToDer(*key.value);
    if(!der)
    {
      AsyncWorker::SetError(der.msg());
      return;
    }

    auto pub = so::rsa::convertPubKeyToDer(*key.value);
    if(!pub)
    {
      AsyncWorker::SetError(pub.msg());
      return;
    }

    m_privDer = der.moveValue();
    m_pubDer = pub.moveValue();
  }

  void OnOK() override
  {
    Napi::HandleScope scope(Env());

    Callback().Call({
      Env().Undefined(),
      Napi::Buffer<uint8_t>::Copy(Env(), m_privDer.data(), m_privDer.size()),
      Napi::Buffer<uint8_t>::Copy(Env(), m_pubDer.data(), m_pubDer.size())
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

} // namespace rsa {

} // namespace
