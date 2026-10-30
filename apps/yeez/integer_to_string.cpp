//===------------------------- string.cpp ---------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "string"
#include "charconv"
#include "limits"
#include "__debug"
_LIBCPP_BEGIN_NAMESPACE_STD
namespace {
template <typename S, typename V>
S i_to_string(const V v)
{
//  numeric_limits::digits10 returns value less on 1 than desired for unsigned numbers.
//  For example, for 1-byte unsigned value digits10 is 2 (999 can not be represented),
//  so we need +1 here.
    constexpr size_t bufsize = numeric_limits<V>::digits10 + 2;  // +1 for minus, +1 for digits10
    char buf[bufsize];
    const auto res = to_chars(buf, buf + bufsize, v);
    _LIBCPP_ASSERT(res.ec == errc(), "bufsize must be large enough to accomodate the value");
    return S(buf, res.ptr);
}

}
string  to_string (int val)                { return i_to_string< string>(val); }
string  to_string (long val)               { return i_to_string< string>(val); }
string  to_string (long long val)          { return i_to_string< string>(val); }
string  to_string (unsigned val)           { return i_to_string< string>(val); }
string  to_string (unsigned long val)      { return i_to_string< string>(val); }
string  to_string (unsigned long long val) { return i_to_string< string>(val); }

_LIBCPP_END_NAMESPACE_STD
