#pragma once
#include <algorithm>
#include <memory>
#include <string>
#include <Windows.h>

template <typename T> struct allocator {
	using value_type = T;
	using propagate_on_container_move_assignment =
		typename std::allocator_traits<std::allocator<T>>
		::propagate_on_container_move_assignment;

	constexpr allocator() = default;
	constexpr allocator(const allocator&) = default;
	template <class U> constexpr allocator(const allocator<U>&) noexcept {}

	static T* allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }
	static void deallocate(T* p, std::size_t n) {
		SecureZeroMemory(p, n * sizeof * p);
		std::allocator<T>{}.deallocate(p, n);
	}
};

template <typename T, typename U>
constexpr bool operator== (const allocator<T>&, const allocator<U>&) noexcept {
	return true;
}

template <typename T, typename U>
constexpr bool operator!= (const allocator<T>&, const allocator<U>&) noexcept {
	return false;
}

using SecureString = std::basic_string<char, std::char_traits<char>,
	allocator<char>>;

using SecureWString = std::basic_string<wchar_t, std::char_traits<wchar_t>,
	allocator<wchar_t>>;

namespace std {
	// Zero the strings own memory on destruction
	template<> SecureString::~basic_string() {
		using X = basic_string<char, char_traits<char>,
			::allocator<unsigned char>>;
		((X*)this)->~X();
		SecureZeroMemory(this, sizeof * this);
	}

	template<> SecureWString::~basic_string() {
		using X = basic_string<wchar_t, char_traits<wchar_t>,
			::allocator<unsigned char>>;
		((X*)this)->~X();
		SecureZeroMemory(this, sizeof * this);
	}
}