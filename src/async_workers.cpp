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

class BufferReverseAsync : public Napi::AsyncWorker
{
public:
  BufferReverseAsync(Napi::Function &callback, std::unique_ptr<uint8_t[]> data, size_t size)
    : AsyncWorker(callback), m_inBuffer{std::move(data)}, m_size{size}
  {}

  void Execute() override
  {
    for(size_t beg = 0, end = m_size - 1; beg < end; ++beg, --end)
    {
      const auto tmp = m_inBuffer[beg];
      m_inBuffer[beg] = m_inBuffer[end];
      m_inBuffer[end] = tmp;
    }

  }

  void OnOK() override
  {
    Napi::HandleScope scope(Env()); 

    Callback().Call({
        Env().Null(),
        Napi::Buffer<uint8_t>::New(
            Env(),
            m_inBuffer.release(),
            m_size,
            byte_array_delete,
            "BYTE ARRAY REVERSED")
    });
  }

private:
  std::unique_ptr<uint8_t[]> m_inBuffer{nullptr};
  size_t m_size {0};
};

class RSA_PemPrivKeyToDerAsync : public Napi::AsyncWorker
{
public:
  RSA_PemPrivKeyToDerAsync(Napi::Function &callback, std::string pem)
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
        Env().Null(),
        Napi::Buffer<uint8_t>::New(
            Env(),
            m_outDer.release(),
            m_size,
            byte_array_delete,
            "RSA_PemPrivKeyToDerAsync")
    });
  }

private:
  std::string m_pem;
  std::unique_ptr<uint8_t[]> m_outDer;
  size_t m_size;
};

} // namespace
