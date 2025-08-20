#pragma once

#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <utility>

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

	template <typename T>
	T *PushArray(u64 ArrayCount, u64 Alignment = 8) {
		T *Result = (T *)Push(sizeof(T) * ArrayCount, Alignment);
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

	string8(const char *CString) : Length(0) {
		Data = (const char8 *)CString;
		char8 *c = (char8 *)CString;
		while (*c++) {
			Length += 1;
		}
	}
	string8(const char *CString, u32 InLength)  : Data((const char8 *)CString), Length(InLength) { }

	string8(u64 Value, memory_arena *Arena = &Temp) {
		*this = FromUnsignedInt(Arena, Value);
	}
	string8(s64 Value, memory_arena *Arena = &Temp) {
		*this = FromSignedInt(Arena, Value);
	}

	constexpr char8 operator[] (u32 Index) const {
		char8 Result = (Index < Length) ? Data[Index] : 0;
		return Result;
	}

	constexpr string8 Substring(u32 Start, u32 End = UINT32_MAX) const {
		if (End == UINT32_MAX) End = Length;
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
	linked_list(const linked_list<T> &InLinkedList) {
		Arena = InLinkedList.Arena;
		Head = InLinkedList.Head;
		Tail = InLinkedList.Tail;
	}

	T *Push(const T &Value) {
		node *NewNode = Arena->Push<node>();
		NewNode->Value = Value;
		NewNode->Next = &SentinelNode;
		Tail->Next = NewNode;
		Tail = NewNode;
		return &NewNode->Value;
	}

	operator bool () const {
		return Head->Next != &SentinelNode;
	}

	iterator begin() const { return iterator(Head->Next); }
	iterator end() const { return iterator(&SentinelNode); }
};

struct string8_builder {
	memory_arena *Arena;

	u32 FinalStringLength = 0;
	linked_list<string8> StringList;

	string8_builder(memory_arena *InArena = &Temp) : Arena(InArena) {
		StringList = linked_list<string8>(Arena);
	}

	void Push(const string8 &InString) {
		StringList.Push(InString);
		FinalStringLength += InString.Length;
	}

	template <typename t, typename... args>
	void FormatAndPush(const string8 &FormatString, t &&Arg, args&&... Args);

	string8_builder operator + (const string8 &InString) {
		Push(InString);
		return *this;
	}

	template <typename T>
	void operator += (const T &Value) {
		if constexpr (std::is_integral_v<T> && std::is_unsigned_v<T>) {
			string8 String = string8::FromUnsignedInt(Arena, (u64)Value);
			Push(String);
		} else if constexpr (std::is_integral_v<T> && std::is_signed_v<T>) {
			string8 String = string8::FromSignedInt(Arena, (s64)Value);
			Push(String);
		} else {
			Push(string8(Value));
		}
	}

	void Combine(string8_builder &Other) {
		this->StringList.Tail->Next = Other.StringList.Head->Next;
		this->StringList.Tail = Other.StringList.Tail;
		FinalStringLength += Other.FinalStringLength;

		Other.StringList.Head->Next = &linked_list<string8>::SentinelNode;
		Other.FinalStringLength = 0;
	}

	void operator += (string8_builder &Other) {
		Combine(Other);
	}
	void operator += (string8_builder &&Other) {
		Combine(Other);
	}

	string8 FinalizeString() {
		char8 *Buffer = (char8 *)Arena->Push(FinalStringLength);

		char8 *BufferEnd = Buffer;

		for (const string8 &String : StringList) {
			memcpy(BufferEnd, String.Data, String.Length);
			BufferEnd += String.Length;
		}

		u64 CalculatedLength = BufferEnd - Buffer;
		assert(CalculatedLength == FinalStringLength);

		return string8(Buffer, FinalStringLength);
	}
};

string8_builder string8::operator + (const string8 &Other) {
	string8_builder Builder(&Temp);
	Builder.Push(*this);
	Builder.Push(Other);
	return Builder;
}

static inline void FormatImpl(const string8 &FormatString, string8_builder &Builder) {
	Builder.Push(FormatString);
}

template <typename t, typename... args>
static inline void FormatImpl(const string8 &FormatString, string8_builder &Builder, t &&Arg, args&&... Args) {
	u32 i = 0;

	while (i < FormatString.Length && FormatString[i] != '{' && FormatString[i + 1] != '}') {
		i += 1;
	}

	if (i < FormatString.Length) {
		Builder.Push(FormatString.Substring(0, i));

		Builder += (Arg);

		FormatImpl(FormatString.Substring(i + 2), Builder, std::forward<args>(Args)...);
	} else {
		Builder.Push(FormatString);
	}
}

template <typename t, typename... args>
static string8 Format(memory_arena *Arena, const string8 &FormatString, t &&Arg, args&&... Args) {
	string8_builder Builder(Arena);
	FormatImpl(FormatString, Builder, std::forward<t>(Arg), std::forward<args>(Args)...);
	return Builder.FinalizeString();
}

template <typename t, typename... args>
void string8_builder::FormatAndPush(const string8 &FormatString, t &&Arg, args&&... Args) {
	FormatImpl(FormatString, *this, std::forward<t>(Arg), std::forward<args>(Args)...);
}

static void Print(const string8 &String) {
	fwrite(String.Data, 1, String.Length, stdout);
}

template <typename t, typename... args>
static void Print(const string8 &FormatString, t &&Arg, args&&... Args) {
	arena_auto_pop AutoPop(&Temp);
	string8_builder Builder(&Temp);
	FormatImpl(FormatString, Builder, std::forward<t>(Arg), std::forward<args>(Args)...);
	string8 Result = Builder.FinalizeString();
	Print(Result);
}

#define ANSI_GREEN u8"\033[0;32m"
#define ANSI_RED u8"\033[0;31m"
#define ANSI_YELLOW u8"\033[0;33m"
#define ANSI_BLUE u8"\033[0;34m"
#define ANSI_MAGENTA u8"\033[0;35m"
#define ANSI_CYAN u8"\033[0;36m"
#define ANSI_BOLD u8"\033[1m"
#define ANSI_UNDERLINE u8"\033[4m"
#define ANSI_BLACK u8"\033[0;30m"
#define ANSI_WHITE u8"\033[0;37m"
#define ANSI_RESET u8"\033[0m"

template <typename value_type, typename error_type>
struct value_or_error {
	bool HasError = false;
	union {
		value_type Value;
		error_type Error;
	};

	value_or_error(const value_type &InValue) : Value(InValue), HasError(false) { }
	value_or_error(const error_type &InError) : Error(InError), HasError(true) { }

	void SetError(const error_type &InError) {
		HasError = true;
		Error = InError;
	}
};