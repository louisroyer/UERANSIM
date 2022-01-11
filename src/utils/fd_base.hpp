//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <utils/network.hpp>

class FdBase
{
  public:
    static constexpr const int PS_START = 0;
    static constexpr const int PS_END = 15;
    static constexpr const int RLS_IP4 = 16;
    static constexpr const int RLS_IP6 = 17;
    static constexpr const int CMD = 18;

    static constexpr const int SIZE = 19;

  private:
    std::array<int, SIZE> m_fd;
    size_t m_dice;

  public:
    FdBase();
    ~FdBase();

  public:
    void allocate(int id, int fd);
    void release(int id);
    [[nodiscard]] bool contains(int id) const;

    int performSelect(int timeout);

    size_t read(int id, uint8_t *buffer, size_t size);
    void write(int id, uint8_t *buffer, size_t size);

    size_t receive(int id, uint8_t *buffer, size_t size, InetAddress &outAddress);
    void sendTo(int id, uint8_t *buffer, size_t size, const InetAddress &address);
};