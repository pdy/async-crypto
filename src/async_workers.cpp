#include "napi.h"
#include <iostream>

namespace {

void byte_array_delete(Napi::Env /*env*/, uint8_t *arr, const char *hint) 
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

} // namespace
