#pragma once

#include <stdint.h>
#include <assert.h>
#include <stdlib.h>

using s8 = int8_t;
using s16 = int16_t;
using s32 = int32_t;
using s64 = int64_t;
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using char8 = char8_t;

struct memory_arena {
	void *Base = 0;
	u64 Offset = 0;
	u64 Size = 0;

	void Init(u64 InSize) {
		Size = InSize;
		Base = malloc(InSize);
		Offset = 0;
	}

	void *Push(u64 Size, u64 Alignment = 8) {
		uintptr_t Result = (uintptr_t)Base + Offset;
		Result += Alignment - 1;
		Result &= ~(Alignment - 1);

		Offset = (uintptr_t)Result - (uintptr_t)Base + Size;
		assert(Offset < this->Size);

		return (void *)Result;
	}

	template <typename T>
	T *Push(u64 Alignment = 8) {
		constexpr u64 Size = sizeof(T);
		T *Result = (T *)Push(Size);
		*Result = {};
		return Result;
	}

	void Pop(void *Ptr) {
		assert((uintptr_t)Ptr >= (uintptr_t)Base);
		uintptr_t OffsetPointer = (uintptr_t)((u8 *)Base + Offset); 
		assert((uintptr_t)Ptr <= OffsetPointer);
		Offset = (uintptr_t)Ptr - (uintptr_t)Base;
	}

    void Reset() {
        Offset = 0;
    }

    ~memory_arena() {
        free(Base);
    }
};
static memory_arena Temp = {};

struct arena_auto_pop {
	memory_arena *Arena;
	void *Base;

	arena_auto_pop(memory_arena *InArena) {
		Arena = InArena;
		Base = InArena->Base;
	}

	~arena_auto_pop() {
		Arena->Pop(Base);
	}
};

template <typename T>
struct auto_defer {
	T Callback;
	auto_defer(const T &InCallback) : Callback(InCallback) {}
	~auto_defer() {
		Callback();
	}
};

template <typename T>
auto_defer(const T&) -> auto_defer<T>;

#define CONCAT_IMPL(x, y) x##y
#define CONCAT(x, y) CONCAT_IMPL(x, y)
#define OnScopeExit(...) const auto CONCAT(_auto_defer_, __COUNTER__) = auto_defer([&]() { __VA_ARGS__; })
#define ArrayLen(Array) (sizeof(Array) / sizeof(Array[0]))

struct string8_builder;

struct string8 {
	const char8 *Data;
	u32 Length;

	constexpr string8() : Data(0), Length(0) { }

	constexpr string8(const char8 *CString) : Length(0) {
		Data = CString;
		char8 *c = (char8 *)CString;
		while (*c++) {
			Length += 1;
		}
	}

	constexpr string8(const char8 *CString, u32 InLength) : Data(CString), Length(InLength) { }
	string8(u64 Value, memory_arena *Arena = &Temp) {
		*this = FromUnsignedInt(Arena, Value);
	}
	string8(s64 Value, memory_arena *Arena = &Temp) {
		*this = FromSignedInt(Arena, Value);
	}

	char8 operator[] (u32 Index) const {
		char8 Result = (Index < Length) ? Data[Index] : 0;
		return Result;
	}

	string8 Substring(u32 Start, u32 End) const {
		assert(Start <= End && End <= Length);
		string8 Result;
		Result.Data = Data + Start;
		Result.Length = End - Start;
		return Result;
	}

	char *ToCString(memory_arena *Arena) const {
		char *Result = (char *)Arena->Push(Length + 1);
		memcpy(Result, Data, Length);
		Result[Length] = 0;
		return Result;
	}

	static bool AreEqual(const string8 &A, const string8 &B) {
		if (A.Length != B.Length) return false;
		for (u32 i = 0; i < A.Length; ++i) {
			if (A[i] != B[i]) return false;
		}
		return true;
	}

    bool EndsWith(const string8 &A) {
        if (A.Length > this->Length) return false;
        s32 EndA = A.Length;
        s32 EndB = this->Length;

        while (EndA) {
            if (A.Data[EndA] != this->Data[EndB]) return false;
            EndA -= 1;
            EndB -= 1;
        }

        return true;
    }

	static void Print(const string8 &String) {
		if (String.Length) {
			fwrite(String.Data, 1, String.Length, stdout);
		}
	}

	static string8 FromUnsignedInt(memory_arena *Arena, u64 Value) {
		char8 *Buffer = (char8 *)Arena->Push(20);
		u32 Length = 0;
		do {
			u64 Digit = Value % 10;
			Length += 1;
			Buffer[20 - Length] = '0' + (char8)Digit;
			Value /= 10;
		} while (Value > 0);
		return string8(Buffer + (20 - Length), (u32)Length);
	}
	static string8 FromSignedInt(memory_arena *Arena, s64 Value) {
		char8 *Buffer = (char8 *)Arena->Push(21);
		u32 Length = 0;
		bool isNegative = Value < 0;
		if (isNegative) Value = -Value;
		do {
			u64 Digit = Value % 10;
			Length += 1;
			Buffer[21 - Length] = '0' + (char8)Digit;
			Value /= 10;
		} while (Value > 0);
		if (isNegative) {
			Length += 1;
			Buffer[21 - Length] = '-';
		}
		return string8(Buffer + (21 - Length), Length);
	}

	string8_builder operator + (const string8 &Other);
};

constexpr u64 KB(u64 Bytes) {
	return Bytes * 1024ULL;
}
constexpr u64 MB(u64 Bytes) {
	return KB(Bytes) * 1024ULL;
}
constexpr u64 GB(u64 Bytes) {
	return MB(Bytes) * 1024ULL;
}

template <typename T>
struct linked_list {
	struct node {
		node *Next;
		T Value;
	};
	static inline node SentinelNode = {
		.Next = &SentinelNode,
	};

	struct iterator {
		node *Current;

		iterator(node *Start) : Current(Start) { }

		T &Next() {
			Current = Current->Next;
			return Current->Value;
		}

		T &operator*() const {
			return Current->Value;
		}

		iterator& operator++() {
			Next();
			return *this;
		}

		bool operator!=(const iterator &Other) const {
			return Current != Other.Current;
		}
	};

	memory_arena *Arena = nullptr;
	node *Head;
	node *Tail;

	linked_list() { }
	linked_list(memory_arena *InArena) : Arena(InArena) {
		Head = Arena->Push<node>();
		*Head = SentinelNode;
		Tail = Head;
	}

	T *Push(const T &Value) {
		node *NewNode = Arena->Push<node>();
		NewNode->Value = Value;
		NewNode->Next = &SentinelNode;
		Tail->Next = NewNode;
		Tail = NewNode;
		return &NewNode->Value;
	}

	iterator begin() const { return iterator(Head->Next); }
	iterator end() const { return iterator(&SentinelNode); }
};

#define ANSI_GREEN "\033[0;32m"
#define ANSI_RESET "\033[0m"