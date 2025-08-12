
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <uchar.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

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
};

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

static memory_arena Temp = {};

template <typename T>
struct auto_defer {
	T Callback;
	constexpr auto_defer(const T &InCallback) : Callback(InCallback) {}
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


static string8 LoadFile(memory_arena *Arena, string8 FilePath) {
	arena_auto_pop DeferredPop(&Temp);

	char *Path = FilePath.ToCString(&Temp);

	int FileHandle = open(Path, O_RDONLY);
	if (FileHandle < 0) return {};
	OnScopeExit(close(FileHandle));

	struct stat Stats;
	if (fstat(FileHandle, &Stats) < 0) return {};

	size_t Size = Stats.st_size;
	char8 *Buffer = (char8 *)Arena->Push(Size);

	ssize_t BytesRead = read(FileHandle, Buffer, Size);
	if (BytesRead < 0) return {};


	string8 Result(Buffer, (u32)BytesRead);
	return Result;
}

static string8 LoadPreprocessedFile(memory_arena *Arena, string8 FilePath) {
	arena_auto_pop DeferredPop(&Temp);

	char *Path = FilePath.ToCString(&Temp);

	char CommandBuffer[1024];
	snprintf(CommandBuffer, sizeof(CommandBuffer), "clang -E -P %s", Path);

	FILE *Pipe = popen(CommandBuffer, "r");
	if (!Pipe) return {};

	OnScopeExit(pclose(Pipe));

	string8 Result = {};
	const size_t ChunkSize = 4096;
	Result.Data = (char8 *)Arena->Push(0);
	Result.Length = 0;
	while (true) {
		char8 *Chunk = (char8 *)Arena->Push(ChunkSize);
		size_t BytesRead = fread(Chunk, 1, ChunkSize, Pipe);

		if (BytesRead == 0) {
			Arena->Pop(Chunk);
			break;
		}

		Result.Length += (u32)BytesRead;
	}

	return Result;
}


enum token_type : u32 {
	Identifier = 256,
	IntConstant,
	OperatorDecrement,
	OperatorIncrement,
	KeywordInt,
	KeywordVoid,
	KeywordReturn,
};

struct token {
	token_type Type;
	union {
		u32 Constant;
		string8 String;
	};
};

constexpr inline bool IsAlpha(const u8 c) {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_';
}
constexpr inline bool IsNumeric(const u8 c) {
	return c >= '0' && c <= '9';
}
constexpr inline bool IsAlphaNumeric(const u8 c) {
	return IsAlpha(c) || IsNumeric(c);
}

constexpr inline bool IsWhitespace(const u8 c) {
	return c == ' ' || c == '\r' || c == '\n' || c == '\t';
}

struct keyword_metadata {
	string8 String;
	token_type TokenType;
};

static keyword_metadata Keywords[] = {
	{ string8(u8"int"), KeywordInt },
	{ string8(u8"void"), KeywordVoid },
	{ string8(u8"return"), KeywordReturn }
};

inline token_type GetAlphaNumericType(const string8 &String) {
	for (u32 i = 0; i < ArrayLen(Keywords); ++i) {
		if (string8::AreEqual(String, Keywords[i].String)) {
			return Keywords[i].TokenType;
		}
	}

	return token_type::Identifier;
}

[[noreturn]]
void Fail(const char * Message, ...) {
	va_list Args;
	va_start(Args, Message);
	vfprintf(stderr, Message, Args);
	va_end(Args);
	fprintf(stderr, "\n");
	exit(1);
}

enum class ast_node_type : u32 {
	Invalid = 0,
	FunctionDeclaration,
	Expression,
	Identifier,
	IntConstant,
	Return,
	UnaryNegate,
	UnaryBitwiseNegate,
};

struct ast_node {
	ast_node_type Type = ast_node_type::Invalid;
	union {
		u64 IntValue;

		struct {
			ast_node *Expression;
		} ReturnStatement;

		struct {
			ast_node *Expression;
		} UnaryOperation;
	};
};

ast_node DefaultAstNode = {
	.Type = ast_node_type::Invalid
};

struct ast_function_declaration {
	string8 Name = {};
	ast_node *FunctionBody = &DefaultAstNode;
};

struct parser_state {
	memory_arena *Arena;

	linked_list<token>::iterator Current;

	const token &AdvanceToken() {
		return Current.Next();
	}
	const token &CurrentToken() {
		return *Current;
	}

	ast_node *PushReturnNode() {
		ast_node *Node = Arena->Push<ast_node>();
		Node->Type = ast_node_type::Return;
		Node->ReturnStatement.Expression = &DefaultAstNode;
		return Node;
	}

	ast_node *PushIntConstantNode(u64 Value) {
		ast_node *Node = Arena->Push<ast_node>();
		Node->Type = ast_node_type::IntConstant;
		Node->IntValue = Value;
		return Node;
	}

	ast_node *PushUnaryOperationNode(ast_node_type Type, ast_node *Expression = &DefaultAstNode) {
		assert(Type == ast_node_type::UnaryNegate || Type == ast_node_type::UnaryBitwiseNegate);
		ast_node *Node = Arena->Push<ast_node>();
		Node->Type = Type;
		Node->UnaryOperation.Expression = Expression;
		return Node;
	}
};

void Expect(bool Condition, const char *Message) {
	if (!Condition) {
		Fail("Parse error: %s", Message);
	}
}

bool IsUnaryOperator(token_type Type) {
	return Type == '~' || Type == '-';
}

ast_node *Expression(parser_state *State) {

	if (State->CurrentToken().Type == '(') {
		State->AdvanceToken();
		ast_node *Node = Expression(State);
		Expect(State->CurrentToken().Type == ')', "Expected ')' to close expression");
		State->AdvanceToken();
		return Node;
	}

	if (IsUnaryOperator(State->CurrentToken().Type)) {
		ast_node_type UnaryType = (State->CurrentToken().Type == '-') ? ast_node_type::UnaryNegate : ast_node_type::UnaryBitwiseNegate;
		State->AdvanceToken();
		ast_node *Result = State->PushUnaryOperationNode(UnaryType);
		Result->UnaryOperation.Expression = Expression(State);
		return Result;
	}

	if (State->CurrentToken().Type == token_type::IntConstant) {
		u64 Value = State->CurrentToken().Constant;
		ast_node *Result = State->PushIntConstantNode(Value);
		State->AdvanceToken();
		return Result;
	}
	Fail("Expected an expression, found token type: %u", State->CurrentToken().Type);
	return &DefaultAstNode;
}

ast_node *ParseStatement(parser_state *State) {
	// For now, we only handle return statements
	Expect(State->CurrentToken().Type == token_type::KeywordReturn, "Expected 'return' keyword");
	State->AdvanceToken();

	ast_node *ReturnNode = State->PushReturnNode();
	ReturnNode->ReturnStatement.Expression = Expression(State);

	Expect(State->CurrentToken().Type == ';', "Expected ';' to end return statement");
	State->AdvanceToken();

	return ReturnNode;
}

linked_list<ast_function_declaration> ParseProgram(parser_state *State) {
	linked_list<ast_function_declaration> FunctionList(State->Arena);

	while (State->CurrentToken().Type == token_type::KeywordInt) {
		ast_function_declaration FunctionDecl = {};

		Expect(State->CurrentToken().Type == token_type::KeywordInt, "Function must return int");
		Expect(State->AdvanceToken().Type == token_type::Identifier, "Expected identifier after 'int' keyword");
		FunctionDecl.Name = State->CurrentToken().String;

		Expect(State->AdvanceToken().Type == '(', "Expected '(' after function name");
		Expect(State->AdvanceToken().Type == token_type::KeywordVoid, "Expected 'void' for function parameters");
		Expect(State->AdvanceToken().Type == ')', "Expected ')' after function parameters");
		Expect(State->AdvanceToken().Type == '{', "Expected '{' to start function body");
		State->AdvanceToken();

		FunctionDecl.FunctionBody = ParseStatement(State);

		Expect(State->CurrentToken().Type == '}', "Expected '}' to end function body");
		State->AdvanceToken();

		FunctionList.Push(FunctionDecl);
	}

	return FunctionList;
}

void PrettyPrintAst(ast_node *Node, u32 Indent = 0) {
	if (Node == &DefaultAstNode) return;

	for (u32 i = 0; i < Indent; ++i) {
		printf("  ");
	}

	switch (Node->Type) {
		case ast_node_type::Return:
			printf("Return Statement:\n");
			PrettyPrintAst(Node->ReturnStatement.Expression, Indent + 1);
			break;
		case ast_node_type::IntConstant:
			printf("Int Constant: %lu\n", Node->IntValue);
			break;
		case ast_node_type::UnaryNegate:
			printf("Unary Negate:\n");
			PrettyPrintAst(Node->UnaryOperation.Expression, Indent + 1);
			break;
		case ast_node_type::UnaryBitwiseNegate:
			printf("Unary Bitwise Not:\n");
			PrettyPrintAst(Node->UnaryOperation.Expression, Indent + 1);
			break;
		default:
			printf("Unknown AST node type\n");
			break;
	}

}

namespace assembly {
	enum class operation {
		Invalid,
		Mov,
		Return,
		Negate,
		BitwiseNegate,
	};
	enum class x64_register {
		Invalid,
		EAX,
		R10D
	};
	enum class operand_type {
		Invalid,
		Immediate,
		Register,
		StackLocation,
	};
	struct operand {
		operand_type Type = operand_type::Invalid;
		union {
			u64 ImmediateValue;
			x64_register Register;
			s64 StackLocation;
		};
	};

	struct instruction {
		operation Op;
		operand Src, Dst;
	};

	struct function {
		string8 Name;
		s64 StackSize;
		linked_list<instruction> Instructions;
	};
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

	void operator += (const string8 &InString) {
		Push(InString);
	}

	string8_builder operator + (const string8 &InString) {
		Push(InString);
		return *this;
	}

	void operator += (const u64 Value) {
		string8 String = string8::FromUnsignedInt(Arena, Value);
		Push(String);
	}
	void operator += (const s64 Value) {
		string8 String = string8::FromSignedInt(Arena, Value);
		Push(String);
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

constexpr string8 RegisterToString(assembly::x64_register Register) {
	switch (Register) {
		case assembly::x64_register::EAX: {
			return string8(u8"%eax");
		} break;
		case assembly::x64_register::R10D: {
			return string8(u8"%r10d");
		} break;
	}

	return {};
}

void EmitMovInstruction(string8_builder &Builder, const assembly::operand &Src, const assembly::operand &Dst) {
	if (Src.Type == assembly::operand_type::StackLocation && Dst.Type == assembly::operand_type::StackLocation) {
		Builder += string8(u8"  movl ") + Src.StackLocation + u8"(%rbp), %r10d\n";
		Builder += string8(u8"  %r10, ") + Dst.StackLocation + u8"(%rbp)\n";
		return;
	}

	if (Src.Type == assembly::operand_type::Immediate) {
		Builder += string8(u8"  movl $") + Src.ImmediateValue + u8", ";
		switch (Dst.Type) {
			case assembly::operand_type::Register: {
				Builder += RegisterToString(Dst.Register) + u8"\n";
				return;
			} break;
			case assembly::operand_type::StackLocation: {
				Builder += string8(Dst.StackLocation) + u8"(%rbp)\n";
				return;
			} break;
		}
	}

	if (Src.Type == assembly::operand_type::Register) {

		if (Dst.Type == assembly::operand_type::Register) {
			if (Src.Register == Dst.Register) return;
		}

		Builder += string8(u8"  movl ") + RegisterToString(Src.Register) + u8", ";
		switch (Dst.Type) {
			case assembly::operand_type::Register: {
				Builder += RegisterToString(Dst.Register) + u8"\n";
				return;
			} break;
			case assembly::operand_type::StackLocation: {
				Builder += string8(Dst.StackLocation) + u8"(%rbp)\n";
				return;
			} break;
		}
	}

	if (Src.Type == assembly::operand_type::StackLocation) {
		Builder += string8(u8"  movl ") + Src.StackLocation + u8"(%rbp), ";
		switch (Dst.Type) {
			case assembly::operand_type::Register: {
				Builder += RegisterToString(Dst.Register) + u8"\n";
				return;
			} break;
		}
	}

	assert(false);
}

void EmitAssemblyToFile(assembly::function *Function, const string8 &FilePath) {
	arena_auto_pop DeferredPop(&Temp);

	char *Path = FilePath.ToCString(&Temp);
	s32 FileDescriptor = open(Path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (FileDescriptor < 0) {
		Fail("Failed to open file for writing: %s", Path);
	}
	OnScopeExit(close(FileDescriptor));

	string8_builder Builder(&Temp);
	Builder += u8".global main\n"
			   u8"main:\n";

	if (Function->StackSize > 0) {
		Builder += u8"  pushq %rbp\n"
					u8"  movq %rsp, %rbp\n";
		Builder += string8(u8"  subq  $") + Function->StackSize + u8", %rsp\n";
	}

	const assembly::operand EAX = { .Type = assembly::operand_type::Register, .Register = assembly::x64_register::EAX };

	for (const assembly::instruction &Instruction : Function->Instructions) {
		switch (Instruction.Op) {
			case assembly::operation::Mov: {
				EmitMovInstruction(Builder, Instruction.Src, Instruction.Dst);
			} break;
			case assembly::operation::BitwiseNegate: {
				EmitMovInstruction(Builder, Instruction.Src, EAX);
				Builder += u8"  not %eax\n";
				EmitMovInstruction(Builder, EAX, Instruction.Dst);
			} break;
			case assembly::operation::Negate: {
				EmitMovInstruction(Builder, Instruction.Src, EAX);
				Builder += u8"  neg %eax\n";
				EmitMovInstruction(Builder, EAX, Instruction.Dst);
			} break;
			case assembly::operation::Return: {
				EmitMovInstruction(Builder, Instruction.Src, Instruction.Dst);
				if (Function->StackSize > 0) {
					Builder += u8"  movq %rbp, %rsp\n"
							u8"  popq %rbp\n";
				}
				Builder += u8"  ret\n";
			} break;
			default:
				break;
		}
	}

	Builder += u8".section .note.GNU-stack,\"\", @progbits\n";

	string8 FinalString = Builder.FinalizeString();
	ssize_t BytesWritten = write(FileDescriptor, FinalString.Data, FinalString.Length);
	if (BytesWritten < 0) {
		Fail("Failed to write to file: %s", Path);
	}
}

namespace ir {
	struct operand {
		enum class type {
			Invalid,
			Temp,
			Constant
		};
		type Type = type::Invalid;
		u64 Value;
	};

	struct instruction {
		enum class opcode {
			Invalid,
			Return,
			Negate,
			BitwiseNegate
		};
		opcode Opcode;
		operand Dst, Src1, Src2;
	};

	struct function {
		string8 Name;
		linked_list<instruction> Instructions;
		u64 TempCount = 0;
	};
};

ir::operand EmitExpressionIR(ir::function *Function, ast_node *ExpressionNode) {
	switch (ExpressionNode->Type) {
		case ast_node_type::IntConstant: {
			return { ir::operand::type::Constant, ExpressionNode->IntValue };
		} break;
		case ast_node_type::UnaryNegate:
		case ast_node_type::UnaryBitwiseNegate: {
			ir::operand Src = EmitExpressionIR(Function, ExpressionNode->UnaryOperation.Expression);
			ir::operand Dst = { ir::operand::type::Temp, Function->TempCount++ };
			ir::instruction::opcode Opcode = (ExpressionNode->Type == ast_node_type::UnaryNegate)
				? ir::instruction::opcode::Negate : ir::instruction::opcode::BitwiseNegate;
			ir::instruction NewInstruction = { .Opcode = Opcode, .Dst = Dst, .Src1 = Src, };
			Function->Instructions.Push(NewInstruction);
			return Dst;
		} break;
		default:;
	}

	return {};
}

ir::function EmitIR(memory_arena *Arena, const linked_list<ast_function_declaration> &Node) {
	const ast_function_declaration &FunctionDecl = *Node.begin();

	ir::function Result;
	Result.Name = FunctionDecl.Name;
	Result.Instructions = linked_list<ir::instruction>(Arena);
	Result.TempCount = 0;

	ir::operand Operand = EmitExpressionIR(&Result, FunctionDecl.FunctionBody->ReturnStatement.Expression);
	ir::instruction ReturnInstruction = {
		.Opcode = ir::instruction::opcode::Return,
		.Src1 = Operand
	};
	Result.Instructions.Push(ReturnInstruction);

	return Result;
}

assembly::operand IROperandToAssemblyOperand(const ir::operand &IROperand) {
	assembly::operand Result = {};
	switch (IROperand.Type) {
		case ir::operand::type::Constant: {
			Result.Type = assembly::operand_type::Immediate;
			Result.ImmediateValue = IROperand.Value;
		} break;
		case ir::operand::type::Temp: {
			Result.Type = assembly::operand_type::StackLocation;
			Result.StackLocation = -(s64)IROperand.Value * 4 - 4;
		} break;
	}
	return Result;
}

void PrintAssemblyInstructions(const assembly::function &Function) {
	arena_auto_pop DeferredPop(&Temp);

	auto PrintOperand = [&](const assembly::operand &Op, string8_builder &Builder) {
		switch (Op.Type) {
			case assembly::operand_type::Immediate: {
				Builder += u8"$";
				Builder += Op.ImmediateValue;
			} break;
			case assembly::operand_type::Register:
				switch (Op.Register) {
					case assembly::x64_register::EAX: Builder += u8"%rax"; break;
					case assembly::x64_register::R10D: Builder += u8"%r10"; break;
				} break;
			case assembly::operand_type::StackLocation: {
				Builder += Op.StackLocation;
				Builder += u8"(%rsp)";
			} break;
			default:;
		}
	};

	string8_builder Builder(&Temp);
	for (const assembly::instruction &Instruction : Function.Instructions) {
		switch (Instruction.Op) {
			case assembly::operation::Negate: {
				Builder += u8"negate ";
				PrintOperand(Instruction.Src, Builder);
				Builder += u8" -> ";
				PrintOperand(Instruction.Dst, Builder);
				Builder += u8"\n";
			} break;
			case assembly::operation::BitwiseNegate: {
				Builder += u8"bitwise_negate ";
				PrintOperand(Instruction.Src, Builder);
				Builder += u8" -> ";
				PrintOperand(Instruction.Dst, Builder);
				Builder += u8"\n";
			} break;
			case assembly::operation::Return: {
				Builder += u8"return ";
				PrintOperand(Instruction.Src, Builder);
				Builder += u8" -> ";
				PrintOperand(Instruction.Dst, Builder);
				Builder += u8"\n";
			} break;
			default: {
			} break;
		}
	}
	string8::Print(Builder.FinalizeString());
}

assembly::function IRFunctionToAssembly(memory_arena *Arena, const ir::function &Function) {
	assembly::function Result;
	Result.Instructions = linked_list<assembly::instruction>(Arena);
	Result.Name = Function.Name;
	Result.StackSize = Function.TempCount * 8;

	for (const ir::instruction &Instruction : Function.Instructions) {
		assembly::instruction AssemblyInstruction = {};
		switch (Instruction.Opcode) {
			case ir::instruction::opcode::Negate: {
				AssemblyInstruction.Op = assembly::operation::Negate;
				AssemblyInstruction.Src = IROperandToAssemblyOperand(Instruction.Src1);
				AssemblyInstruction.Dst = IROperandToAssemblyOperand(Instruction.Dst);
			} break;
			case ir::instruction::opcode::BitwiseNegate: {
				AssemblyInstruction.Op = assembly::operation::BitwiseNegate;
				AssemblyInstruction.Src = IROperandToAssemblyOperand(Instruction.Src1);
				AssemblyInstruction.Dst = IROperandToAssemblyOperand(Instruction.Dst);
			} break;
			case ir::instruction::opcode::Return: {
				AssemblyInstruction.Op = assembly::operation::Return;
				AssemblyInstruction.Dst = { .Type = assembly::operand_type::Register, .Register = assembly::x64_register::EAX };
				AssemblyInstruction.Src = IROperandToAssemblyOperand(Instruction.Src1);
			} break;
			default: {
				continue;
			}
		}
		Result.Instructions.Push(AssemblyInstruction);
	}

	PrintAssemblyInstructions(Result);

	return Result;
}

s32 main(s32 argc, char **argv) {

	if (argc < 2) {
		Fail("No input file provided");
		return -1;
	}

	memory_arena LexerArena = {};
	LexerArena.Init(MB(256));
	Temp.Init(MB(64));

	const string8 FileContents = LoadPreprocessedFile(&LexerArena, (char8 *)argv[1]);

	linked_list<token> TokenList(&LexerArena);

	char8 CharTable[256] = {0};
	CharTable['('] = 1;
	CharTable[')'] = 1;
	CharTable['{'] = 1;
	CharTable['}'] = 1;
	CharTable[';'] = 1;
	CharTable['~'] = 1;
	CharTable['-'] = 1;
	CharTable['+'] = 1;

	u32 LineNumber = 1;
	u32 LastNewLineIndex = 0;

	for (u32 i = 0; i < FileContents.Length;) {
		char8 c = FileContents[i];

		if (IsWhitespace(c)) {
			if (c == '\n') LineNumber += 1;
			i += 1;
			LastNewLineIndex = i;
			continue;
		}

		if (IsAlpha(c)) {
			u32 StartIndex = i;
			do {
				i += 1;
			} while (IsAlphaNumeric(FileContents[i]));

			if (!IsWhitespace(FileContents[i]) && !CharTable[FileContents[i]]) {
				Fail("Invalid identifier or keyword at index %u: '%c' (line %u)", i - LastNewLineIndex, FileContents[i], LineNumber);
			}
			string8 IdentifierOrKeyword = FileContents.Substring(StartIndex, i);
			token_type Type = GetAlphaNumericType(IdentifierOrKeyword);

			token *NewToken = TokenList.Push({ Type });
			NewToken->String = IdentifierOrKeyword;
			continue;
		}

		if (IsNumeric(c)) {
			u32 StartIndex = i;

			do {
				i += 1;
			} while (IsNumeric(FileContents[i]));

			if (IsAlpha(FileContents[i]) || FileContents[i] == '_') {
				Fail("Invalid numeric constant at index %u: '%c' (line %u)", i - LastNewLineIndex, FileContents[i], LineNumber);
			}
			if (!IsWhitespace(FileContents[i]) && !CharTable[FileContents[i]]) {
				Fail("Invalid numeric constant at index %u: '%c' (line %u)", i - LastNewLineIndex, FileContents[i], LineNumber);
			}

			u32 Value = 0;
			const u32 EndIndex = i;
			for (u32 Index = StartIndex; Index < EndIndex; ++Index) {
				Value *= 10;
				Value += FileContents[Index] - '0';
			}

			token *NewToken = TokenList.Push({ token_type::IntConstant });
			NewToken->Constant = Value;
			continue;
		}

		if (c == '-') {
			if (FileContents[i + 1] == '-') {
				token *NewToken = TokenList.Push({ token_type::OperatorDecrement });
				i += 2;
				continue;
			}
		}

		if (c == '+') {
			if (FileContents[i + 1] == '+') {
				token *NewToken = TokenList.Push({ token_type::OperatorIncrement });
				i += 2;
				continue;
			}
		}

		if (CharTable[c]) {
			token *NewToken = TokenList.Push({ (token_type)c });
			i += 1;
			continue;
		}

		Fail("Unexpected character '%c' at index %u (line %u)", c, i - LastNewLineIndex, LineNumber);
	}

	memory_arena ParserArena = {};
	ParserArena.Init(MB(256));

	parser_state ParserState = {
		.Arena = &ParserArena,
		.Current = TokenList.begin()
	};
	linked_list<ast_function_declaration> FunctionList = ParseProgram(&ParserState);

	memory_arena IRArena = {};
	IRArena.Init(MB(256));
	ir::function IRFunction = EmitIR(&IRArena, FunctionList);

	memory_arena AssemblyArena = {};
	AssemblyArena.Init(MB(256));
	assembly::function AssemblyFunction = IRFunctionToAssembly(&AssemblyArena, IRFunction);

	constexpr string8 OutputFileName = string8(u8"output.s");
	EmitAssemblyToFile(&AssemblyFunction, OutputFileName);

	return 0;
}