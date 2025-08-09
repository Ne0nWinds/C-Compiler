
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

static memory_arena Temp = {};

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
	KeywordInt,
	KeywordVoid,
	KeywordReturn,
};

struct token {
	token *Next;
	token_type Type;
	union {
		u64 Constant;
		string8 String;
	};
};

static token DefaultToken = {
	.Next = &DefaultToken,
	.Type = (token_type)0,
};

token *CreateNewToken(memory_arena *Arena, token_type Type) {
	token *NewToken = (token *)Arena->Push(sizeof(token));
	NewToken->Next = &DefaultToken;
	NewToken->Type = Type;
	return NewToken;
}

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
	Program,
	FunctionDeclaration,
	Statement,
	Expression,
	Identifier,
	IntConstant
};

struct ast_node {
	ast_node_type Type = ast_node_type::Invalid;
	union {
		u64 IntValue;

		struct {
			ast_node *Next;
			ast_node *FunctionBody;
			string8 Name;
		} FunctionDeclaration;

		struct {
			ast_node *Body;
		} Statement;

		struct {
			ast_node *FunctionDeclaration;
		} Program;
	};
};

ast_node DefaultAstNode = {
	.Type = ast_node_type::Invalid
};

struct parser_state {
	memory_arena *Arena;
	token *HeadToken;
	token *CurrentToken;

	token *AdvanceToken() {
		CurrentToken = CurrentToken->Next;
		if (!CurrentToken) {
			int volatile k = 1;
		}
		return CurrentToken;
	}

	ast_node *PushFunctionDeclarationNode() {
		ast_node *Node = Arena->Push<ast_node>();
		Node->Type = ast_node_type::FunctionDeclaration;
		Node->FunctionDeclaration.Next = &DefaultAstNode;
		Node->FunctionDeclaration.FunctionBody = &DefaultAstNode;
		return Node;
	}

	ast_node *PushStatementNode() {
		ast_node *Node = Arena->Push<ast_node>();
		Node->Type = ast_node_type::Statement;
		Node->Statement.Body = &DefaultAstNode;
		return Node;
	}

	ast_node *PushIntConstantNode(u64 Value) {
		ast_node *Node = Arena->Push<ast_node>();
		Node->Type = ast_node_type::IntConstant;
		Node->IntValue = Value;
		return Node;
	}
};

void Expect(bool Condition, const char *Message) {
	if (!Condition) {
		Fail("Parse error: %s", Message);
	}
}

ast_node *Expression(parser_state *State) {
	Expect(State->CurrentToken->Type == token_type::IntConstant, "Expected integer constant");

	u64 Value = State->CurrentToken->Constant;
	ast_node *Node = State->PushIntConstantNode(Value);
	State->AdvanceToken();

	return Node;
}

ast_node *ParseStatement(parser_state *State) {
	// For now, we only handle return statements
	Expect(State->CurrentToken->Type == token_type::KeywordReturn, "Expected 'return' keyword");
	State->AdvanceToken();

	ast_node *ReturnNode = State->PushStatementNode();
	ReturnNode->Statement.Body = Expression(State);

	Expect(State->CurrentToken->Type == ';', "Expected ';' to end return statement");
	State->AdvanceToken();

	return ReturnNode;
}

ast_node *ParseProgram(parser_state *State) {
	ast_node *Root = State->Arena->Push<ast_node>();
	Root->Type = ast_node_type::Program;
	Root->Program.FunctionDeclaration = &DefaultAstNode;

	while (State->CurrentToken->Type == token_type::KeywordInt) {
		ast_node *FunctionNode = State->PushFunctionDeclarationNode();
		FunctionNode->FunctionDeclaration.Next = Root->Program.FunctionDeclaration;
		Root->Program.FunctionDeclaration = FunctionNode;

		Expect(State->CurrentToken->Type == token_type::KeywordInt, "Function must return int");
		Expect(State->AdvanceToken()->Type == token_type::Identifier, "Expected identifier after 'int' keyword");
		FunctionNode->FunctionDeclaration.Name = State->CurrentToken->String;

		Expect(State->AdvanceToken()->Type == '(', "Expected '(' after function name");
		Expect(State->AdvanceToken()->Type == token_type::KeywordVoid, "Expected 'void' for function parameters");
		Expect(State->AdvanceToken()->Type == ')', "Expected ')' after function parameters");
		Expect(State->AdvanceToken()->Type == '{', "Expected '{' to start function body");
		State->AdvanceToken();

		FunctionNode->FunctionDeclaration.FunctionBody = ParseStatement(State);

		Expect(State->CurrentToken->Type == '}', "Expected '}' to end function body");
		State->AdvanceToken();
	}

	return Root;
}

void PrettyPrintAst(ast_node *Node, int Indent = 0) {
	if (Node == &DefaultAstNode) return;

	for (int i = 0; i < Indent; ++i) {
		printf("  ");
	}

	switch (Node->Type) {
		case ast_node_type::Program:
			printf("Program:\n");
			PrettyPrintAst(Node->Program.FunctionDeclaration, Indent + 1);
			break;
		case ast_node_type::FunctionDeclaration: {
			const string8 &Name = Node->FunctionDeclaration.Name;
			printf("Function Declaration: %.*s\n", Name.Length, (char *)Name.Data);
			PrettyPrintAst(Node->FunctionDeclaration.FunctionBody, Indent + 1);
			PrettyPrintAst(Node->FunctionDeclaration.Next, Indent);
		} break;
		case ast_node_type::Statement:
			printf("Statement:\n");
			PrettyPrintAst(Node->Statement.Body, Indent + 1);
			break;
		case ast_node_type::IntConstant:
			printf("Int Constant: %lu\n", Node->IntValue);
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
		Return
	};
	enum class operand_type {
		Invalid,
		Register,
		Immediate,
	};
	struct operand {
		operand_type Type = operand_type::Invalid;
		union {
			u64 ImmediateValue;
			u32 RegisterIndex;
		};
	};

	struct instruction {
		operation Op;
		operand Src, Dst;
		instruction *Next;

		instruction();
	};

	struct function {
		string8 Name;
		instruction *Instructions;
		function *Next;

		function();
	};

	static instruction DefaultInstruction = {};

	instruction::instruction() {
		Op = operation::Invalid;
		Src.Type = operand_type::Invalid;
		Dst.Type = operand_type::Invalid;
		Next = &DefaultInstruction;
	}

	static function DefaultFunction = { };

	function::function() {
		Name = {};
		Instructions = &DefaultInstruction;
		Next = &DefaultFunction;
	}
};

assembly::instruction *ConvertExpressionToAssembly(memory_arena *Arena, ast_node *Expression) {
	if (Expression->Type != ast_node_type::IntConstant) {
		Fail("Expected an integer constant expression");
	}

	assembly::instruction *Instruction = Arena->Push<assembly::instruction>();
	Instruction->Op = assembly::operation::Mov;
	Instruction->Src = { .Type = assembly::operand_type::Immediate, .ImmediateValue = Expression->IntValue };
	Instruction->Dst = { .Type = assembly::operand_type::Register, .RegisterIndex = 0 };
	Instruction->Next = &assembly::DefaultInstruction;

	return Instruction;
}

assembly::instruction *ConvertStatementToAssembly(memory_arena *Arena, ast_node *Statement) {
	if (Statement->Type != ast_node_type::Statement) {
		Fail("Expected a statement node");
	}

	assembly::instruction *ReturnOp = Arena->Push<assembly::instruction>();
	ReturnOp->Op = assembly::operation::Return;
	ReturnOp->Next = &assembly::DefaultInstruction;

	assembly::instruction *ReturnExpression = ConvertExpressionToAssembly(Arena, Statement->Statement.Body);
	ReturnExpression->Next = ReturnOp;

	return ReturnExpression;
}

assembly::function *ConvertASTToAssembly(memory_arena *Arena, ast_node *Root) {
	ast_node *Current = Root->Program.FunctionDeclaration;

	if (Current->Type != ast_node_type::FunctionDeclaration) {
		Fail("No function was declared");
	}

	assembly::function Result = assembly::DefaultFunction;

	while (Current->Type == ast_node_type::FunctionDeclaration) {
		assembly::function *NewFunction = Arena->Push<assembly::function>();
		NewFunction->Name = Current->FunctionDeclaration.Name;
		NewFunction->Next = Result.Next;
		Result.Next = NewFunction;

		NewFunction->Instructions = ConvertStatementToAssembly(Arena, Current->FunctionDeclaration.FunctionBody);

		Current = Current->FunctionDeclaration.Next;
	}

	return Result.Next;
}

void PrettyPrintAssembly(assembly::function *Function) {
	while (Function != &assembly::DefaultFunction) {
		printf("Function: %.*s\n", Function->Name.Length, (char *)Function->Name.Data);
		assembly::instruction *Instruction = Function->Instructions;
		while (Instruction != &assembly::DefaultInstruction) {
			switch (Instruction->Op) {
				case assembly::operation::Mov:
					printf("  MOV R%d, %lu\n", Instruction->Dst.RegisterIndex, Instruction->Src.ImmediateValue);
					break;
				case assembly::operation::Return:
					printf("  RETURN\n");
					break;
				default:
					printf("  UNKNOWN OPERATION\n");
					break;
			}
			Instruction = Instruction->Next;
		}
		Function = Function->Next;
	}
}

struct string8_node {
	string8_node *Next;
	string8 String;

	string8_node();
};

string8_node SentinalChunk = { };

string8_node::string8_node() {
	this->Next = &SentinalChunk;
	this->String = { 0, 0 };
}

struct string8_builder {
	memory_arena *Arena;

	u32 FinalStringLength = 0;
	string8_node *First;
	string8_node *Last;

	string8_builder(memory_arena *InArena) : Arena(InArena) {
		First = Arena->Push<string8_node>();
		Last = First;
	}

	void Push(const string8 &InString) {
		string8_node *NewNode = Arena->Push<string8_node>();
		NewNode->String = InString;

		Last->Next = NewNode;
		Last = NewNode;

		FinalStringLength += InString.Length;
	}

	void operator += (const string8 &InString) {
		Push(InString);
	}

	string8 FinalizeString() {
		char8 *Buffer = (char8 *)Arena->Push(FinalStringLength);

		char8 *BufferEnd = Buffer;
		string8_node *Current = First;
		while (Current != &SentinalChunk) {
			memcpy(BufferEnd, Current->String.Data, Current->String.Length);
			BufferEnd += Current->String.Length;
			Current = Current->Next;
		}

		return string8(Buffer, FinalStringLength);
	}
};

void EmitAssemblyToFile(assembly::function *Function, const string8 &FilePath) {
	arena_auto_pop DeferredPop(&Temp);

	char *Path = FilePath.ToCString(&Temp);
	s32 FileDescriptor = open(Path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (FileDescriptor < 0) {
		Fail("Failed to open file for writing: %s", Path);
	}
	OnScopeExit(close(FileDescriptor));

	string8_builder Builder(&Temp);
	Builder += u8".global main\n";
	Builder += u8"main:\n";

	assembly::instruction *Instruction = Function->Instructions;
	while (Instruction != &assembly::DefaultInstruction) {
		switch (Instruction->Op) {
			case assembly::operation::Mov:
				Builder += u8"  movl $";
				Builder += string8::FromUnsignedInt(&Temp, (u32)Instruction->Src.ImmediateValue);
				Builder += u8", %eax\n";
				break;
			case assembly::operation::Return:
				Builder += u8"  ret\n";
				break;
			default:
				break;
		}
		Instruction = Instruction->Next;
	}

	Builder += u8".section .note.GNU-stack,\"\", @progbits\n";

	string8 FinalString = Builder.FinalizeString();
	ssize_t BytesWritten = write(FileDescriptor, FinalString.Data, FinalString.Length);
	if (BytesWritten < 0) {
		Fail("Failed to write to file: %s", Path);
	}
}

s32 main(s32 argc, char **argv) {

	if (argc < 2) return -1;

	memory_arena LexerArena = {};
	LexerArena.Init(MB(256));

	Temp.Init(MB(64));

	const string8 FileContents = LoadPreprocessedFile(&LexerArena, (char8 *)argv[1]);

	token Head = {};
	token *Tail = &Head;

	char8 CharTable[256] = {0};
	CharTable['('] = 1;
	CharTable[')'] = 1;
	CharTable['{'] = 1;
	CharTable['}'] = 1;
	CharTable[';'] = 1;

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

			token *NewToken = CreateNewToken(&LexerArena, Type);
			NewToken->String = IdentifierOrKeyword;
			Tail->Next = NewToken;
			Tail = NewToken;
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

			u32 EndIndex = i;
			u64 Value = 0;
			do {
				EndIndex -= 1;
				Value *= 10;
				Value += FileContents[EndIndex] - '0';
			} while (EndIndex != StartIndex);

			token *NewToken = CreateNewToken(&LexerArena, token_type::IntConstant);
			NewToken->Constant = Value;
			Tail->Next = NewToken;
			Tail = NewToken;
			continue;
		}

		if (CharTable[c]) {
			token *NewToken = CreateNewToken(&LexerArena, (token_type)c);
			Tail->Next = NewToken;
			Tail = NewToken;
			i += 1;
			continue;
		}

		Fail("Unexpected character '%c' at index %u (line %u)", c, i - LastNewLineIndex, LineNumber);
	}

	memory_arena ParserArena = {};
	ParserArena.Init(MB(256));

	parser_state ParserState = {
		.Arena = &ParserArena,
		.HeadToken = Head.Next,
		.CurrentToken = Head.Next
	};

	ast_node *AST = ParseProgram(&ParserState);
	PrettyPrintAst(AST);

	assembly::function *FunctionList = ConvertASTToAssembly(&ParserArena, AST);
	PrettyPrintAssembly(FunctionList);

	EmitAssemblyToFile(FunctionList, string8(u8"output.s"));

	return 0;
}