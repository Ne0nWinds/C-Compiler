#include <string.h>
#include <stdio.h>
#include <uchar.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "base.h"

#ifdef RUN_UNIT_TESTS
#define XBYAK_NO_EXCEPTION 
#define XBYAK_USE_OP_NAMES
#include "xbyak/xbyak.h"
#include "unit_tests.cpp"
#endif

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

	string8 Command = Format(&Temp, "clang -E -P {}", FilePath);

	FILE *Pipe = popen(Command.ToCString(&Temp), "r");
	if (!Pipe) return {};

	OnScopeExit(pclose(Pipe));

	string8 Result = {};
	const size_t ChunkSize = 1024 * 4;
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

constexpr inline bool IsAlpha(const char8 c) {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_';
}
constexpr inline bool IsNumeric(const char8 c) {
	return c >= '0' && c <= '9';
}
constexpr inline bool IsAlphaNumeric(const char8 c) {
	return IsAlpha(c) || IsNumeric(c);
}

constexpr inline bool IsWhitespace(const char8 c) {
	return c == ' ' || c == '\r' || c == '\n' || c == '\t';
}

struct keyword_metadata {
	string8 String;
	token_type TokenType;
};

static keyword_metadata Keywords[] = {
	{ string8("int"), KeywordInt },
	{ string8("void"), KeywordVoid },
	{ string8("return"), KeywordReturn }
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
void PrintError(const char * Message, ...) {
	va_list Args;
	va_start(Args, Message);
	vfprintf(stderr, Message, Args);
	va_end(Args);
	fprintf(stderr, "\n");
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

	Add,
	Subtract,
	Multiply,
	Division,
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

		struct {
			ast_node *Left;
			ast_node *Right;
		} BinaryOperation;
	};
};

ast_node DefaultAstNode = {
	.Type = ast_node_type::Invalid
};

struct ast_function_declaration {
	string8 Name = {};
	ast_node *FunctionBody = &DefaultAstNode;
};

struct parser_error {
	string8 Message;
	token Token;
};

struct parser_state {
	memory_arena *Arena;
	linked_list<token>::iterator Current;
	bool HasError = false;
	parser_error Error;

	const token &AdvanceToken() {
		return Current.Next();
	}
	const token &CurrentToken() const {
		return *Current;
	}
	void Expect(char ExpectedType, string8 Message) {
		Expect((token_type)ExpectedType, Message);
	}
	void Expect(token_type ExpectedType, const string8 &Message) {
		const token &CurrentToken = *Current;
		if (CurrentToken.Type != ExpectedType && !HasError) {
			HasError = true;
			Error = parser_error{ Message, CurrentToken };
		}
	}
	void ExpectAndAdvance(token_type ExpectedType, const string8 &Message) {
		Expect(ExpectedType, Message);
		AdvanceToken();
	}
	void ExpectAndAdvance(char ExpectedType, const string8 &Message) {
		ExpectAndAdvance((token_type)ExpectedType, Message);
	}
	void SetErrorMessage(const string8 &Message) {
		if (!HasError) {
			HasError = true;
			Error = parser_error{ Message, CurrentToken() };
		}
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

static void Expect(bool Condition, const char *Message) {
	if (!Condition) {
		PrintError("Parse error: %s", Message);
	}
}

static bool IsUnaryOperator(token_type Type) {
	return Type == '~' || Type == '-';
}

static ast_node *Expression(parser_state *State);

static ast_node *Factor(parser_state *State) {
	if (State->CurrentToken().Type == token_type::IntConstant) {
		u64 Value = State->CurrentToken().Constant;
		ast_node *Result = State->PushIntConstantNode(Value);
		State->AdvanceToken();
		return Result;
	}

	if (IsUnaryOperator(State->CurrentToken().Type)) {
		ast_node_type UnaryType = (State->CurrentToken().Type == '-') ? ast_node_type::UnaryNegate : ast_node_type::UnaryBitwiseNegate;
		State->AdvanceToken();
		ast_node *Result = State->PushUnaryOperationNode(UnaryType);
		Result->UnaryOperation.Expression = Factor(State);
		return Result;
	}

	if (State->CurrentToken().Type == '(') {
		State->AdvanceToken();
		ast_node *Node = Expression(State);
		State->ExpectAndAdvance(')', "Expected ')' to close expression");
		return Node;
	}

	State->SetErrorMessage("Expected an expression");
	return &DefaultAstNode;
}

static ast_node *Expression(parser_state *State) {

	ast_node *Result = Factor(State);

	while (State->CurrentToken().Type == '+' || State->CurrentToken().Type == '-') {
		const token_type TokenType = State->CurrentToken().Type;
		State->AdvanceToken();

		ast_node *BinaryNode = State->Arena->Push<ast_node>();
		BinaryNode->Type = (TokenType == '+') ? ast_node_type::Add : ast_node_type::Subtract;
		BinaryNode->BinaryOperation.Left = Result;
		BinaryNode->BinaryOperation.Right = Factor(State);

		Result = BinaryNode;
	}

	return Result;
}

static ast_node *ParseStatement(parser_state *State) {
	State->ExpectAndAdvance(token_type::KeywordReturn, "Expected 'return' keyword");

	ast_node *ReturnNode = State->PushReturnNode();
	ReturnNode->ReturnStatement.Expression = Expression(State);

	State->ExpectAndAdvance(';', "Expected ';' to end return statement");

	return ReturnNode;
}

using parse_result = value_or_error<linked_list<ast_function_declaration>, parser_error>;
static parse_result ParseProgram(parser_state *State) {
	linked_list<ast_function_declaration> FunctionList(State->Arena);

	while (State->CurrentToken().Type == token_type::KeywordInt) {
		ast_function_declaration FunctionDecl = {};

		State->ExpectAndAdvance(token_type::KeywordInt, "Function must return int");
		State->ExpectAndAdvance(token_type::Identifier, "Expected identifier after 'int' keyword");
		FunctionDecl.Name = State->CurrentToken().String;

		State->ExpectAndAdvance('(', "Expected '(' after function name");
		State->ExpectAndAdvance(token_type::KeywordVoid, "Expected 'void' for function parameters");
		State->ExpectAndAdvance(')', "Expected ')' after function parameters");
		State->ExpectAndAdvance('{', "Expected '{' to start function body");

		FunctionDecl.FunctionBody = ParseStatement(State);

		State->ExpectAndAdvance('}', "Expected '}' to end function body");

		FunctionList.Push(FunctionDecl);
	}

	return !State->HasError ? parse_result(FunctionList) : parse_result(State->Error);
}

static void PrettyPrintAst(ast_node *Node, u32 Indent = 0) {
	if (Node == &DefaultAstNode) return;

	for (u32 i = 0; i < Indent; ++i) {
		Print("  ");
	}

	switch (Node->Type) {
		case ast_node_type::Return:
			Print("Return Statement:\n");
			PrettyPrintAst(Node->ReturnStatement.Expression, Indent + 1);
			break;
		case ast_node_type::IntConstant:
			Print("Int Constant: %lu\n", Node->IntValue);
			break;
		case ast_node_type::UnaryNegate:
			Print("Unary Negate:\n");
			PrettyPrintAst(Node->UnaryOperation.Expression, Indent + 1);
			break;
		case ast_node_type::UnaryBitwiseNegate:
			Print("Unary Bitwise Not:\n");
			PrettyPrintAst(Node->UnaryOperation.Expression, Indent + 1);
			break;
		default:
			Print("Unknown AST node type\n");
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
		Add,
		Subtract
	};
	enum x64_register {
		Invalid,
		EAX,
		R10D,
		Count
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
		operand Src1, Src2, Dst;
	};

	struct function {
		string8 Name;
		s64 StackSize;
		linked_list<instruction> Instructions;
	};
};

constexpr string8 RegisterToString(assembly::x64_register Register) {
	switch (Register) {
		case assembly::x64_register::EAX: {
			return string8("%eax");
		} break;
		case assembly::x64_register::R10D: {
			return string8("%r10d");
		} break;
	}

	return {};
}

static void EmitMovInstruction(string8_builder &Builder, const assembly::operand &Src, const assembly::operand &Dst) {
	if (Src.Type == assembly::operand_type::StackLocation && Dst.Type == assembly::operand_type::StackLocation) {
		Builder.FormatAndPush("  movl {}(%rbp), %r10d\n", Src.StackLocation);
		Builder.FormatAndPush("  movl %r10d, {}(%rbp)\n", Dst.StackLocation);
		return;
	}

	if (Src.Type == assembly::operand_type::Immediate) {
		Builder.FormatAndPush("movl {}, ", Src.ImmediateValue);
		switch (Dst.Type) {
			case assembly::operand_type::Register: {
				Builder.FormatAndPush("{}\n", RegisterToString(Dst.Register));
				return;
			} break;
			case assembly::operand_type::StackLocation: {
				Builder.FormatAndPush("{}(%rbp)\n", Dst.StackLocation);
				return;
			} break;
		}
	}

	if (Src.Type == assembly::operand_type::Register) {

		if (Dst.Type == assembly::operand_type::Register) {
			if (Src.Register == Dst.Register) return;
		}

		Builder.FormatAndPush("  movl {}, ", RegisterToString(Src.Register));
		switch (Dst.Type) {
			case assembly::operand_type::Register: {
				Builder += RegisterToString(Dst.Register) + "\n";
				return;
			} break;
			case assembly::operand_type::StackLocation: {
				Builder.FormatAndPush("{}(%rbp)\n", Dst.StackLocation);
				return;
			} break;
		}
	}

	if (Src.Type == assembly::operand_type::StackLocation) {
		Builder += string8("  movl ") + Src.StackLocation + "(%rbp), ";
		switch (Dst.Type) {
			case assembly::operand_type::Register: {
				Builder += RegisterToString(Dst.Register) + "\n";
				return;
			} break;
		}
	}

	assert(false);
}

#ifdef RUN_UNIT_TESTS
static Xbyak::Reg32 X64Registers[] = {
	[assembly::x64_register::Invalid] = Xbyak::Reg32(0),
	[assembly::x64_register::EAX] = Xbyak::util::eax,
	[assembly::x64_register::R10D] = Xbyak::util::r10d
};

using main_function_type = s32(*)();
static void LiveJITAssembly(assembly::function *Function, Xbyak::CodeGenerator &x64) {
	arena_auto_pop DeferredPop(&Temp);

	using namespace Xbyak;
	using namespace Xbyak::util;

	if (Function->StackSize > 0) {
		x64.push(rbp);
		x64.mov(rbp, rsp);
	}

	Reg32 X64Registers[(u32)assembly::x64_register::Count];
	X64Registers[(u32)assembly::x64_register::EAX] = eax;
	X64Registers[(u32)assembly::x64_register::R10D] = r10d;


	const auto EmitMovInstruction = [&x64, &X64Registers](assembly::operand Src, assembly::operand Dst) {
		if (Src.Type == assembly::operand_type::StackLocation && Dst.Type == assembly::operand_type::StackLocation) {
			x64.mov(r10d, dword[rbp + Src.StackLocation]);
			x64.mov(dword[rbp + Dst.StackLocation], r10d);
			return;
		}

		if (Src.Type == assembly::operand_type::Immediate && Dst.Type == assembly::operand_type::Register) {
			Reg32 Register = X64Registers[(u32)Dst.Register];
			x64.mov(Register, (u32)Src.ImmediateValue);
			return;
		}
		if (Src.Type == assembly::operand_type::StackLocation && Dst.Type == assembly::operand_type::Register) {
			Reg32 DstRegister = X64Registers[(u32)Dst.Register];
			x64.mov(DstRegister, dword[rbp + Src.StackLocation]);
			return;
		}
		if (Src.Type == assembly::operand_type::Register && Dst.Type == assembly::operand_type::StackLocation) {
			Reg32 SrcRegister = X64Registers[(u32)Src.Register];
			x64.mov(dword[rbp + Dst.StackLocation], SrcRegister);
			return;
		}

		assert(false);
	};

	constexpr assembly::operand EAX = { .Type = assembly::operand_type::Register, .Register = assembly::x64_register::EAX };

	for (const assembly::instruction &Instruction : Function->Instructions) {
		switch (Instruction.Op) {
			case assembly::operation::Mov: {
				EmitMovInstruction(Instruction.Src1, Instruction.Dst);
			} break;
			case assembly::operation::BitwiseNegate: {
				EmitMovInstruction(Instruction.Src1, EAX);
				x64.not(eax);
				EmitMovInstruction(EAX, Instruction.Dst);
			} break;
			case assembly::operation::Negate: {
				EmitMovInstruction(Instruction.Src1, EAX);
				x64.neg(eax);
				EmitMovInstruction(EAX, Instruction.Dst);
			} break;
			case assembly::operation::Return: {
				EmitMovInstruction(Instruction.Src1, EAX);
				if (Function->StackSize > 0) {
					x64.mov(rsp, rbp);
					x64.pop(rbp);
				}
				x64.ret();
			} break;
			case assembly::operation::Add: {
				EmitMovInstruction(Instruction.Src1, EAX);
				switch (Instruction.Src2.Type) {
					case assembly::operand_type::Immediate: {
						x64.add(eax, Instruction.Src2.ImmediateValue);
					} break;
					case assembly::operand_type::Register: {
						x64.add(eax, X64Registers[(u32)Instruction.Src2.Register]);
					} break;
					case assembly::operand_type::StackLocation: {
						x64.add(eax, dword[rbp + Instruction.Src2.StackLocation]);
					} break;
				}
				EmitMovInstruction(EAX, Instruction.Dst);
			} break;
			case assembly::operation::Subtract: {
				EmitMovInstruction(Instruction.Src1, EAX);
				switch (Instruction.Src2.Type) {
					case assembly::operand_type::Immediate: {
						x64.sub(eax, Instruction.Src2.ImmediateValue);
					} break;
					case assembly::operand_type::Register: {
						x64.sub(eax, X64Registers[(u32)Instruction.Src2.Register]);
					} break;
					case assembly::operand_type::StackLocation: {
						x64.sub(eax, dword[rbp + Instruction.Src2.StackLocation]);
					} break;
				}
				EmitMovInstruction(EAX, Instruction.Dst);
			} break;
		}
	}
}
#endif

static void EmitAssemblyToFile(assembly::function *Function, const string8 &FilePath) {
	arena_auto_pop DeferredPop(&Temp);

	char *Path = FilePath.ToCString(&Temp);
	s32 FileDescriptor = open(Path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (FileDescriptor < 0) {
		PrintError("Failed to open file for writing: %s", Path);
	}
	OnScopeExit(close(FileDescriptor));

	string8_builder Builder(&Temp);
	Builder += ".global main\n"
			   "main:\n";

	if (Function->StackSize > 0) {
		Builder += "  pushq %rbp\n"
					"  movq %rsp, %rbp\n";
		Builder += string8("  subq  $") + Function->StackSize + ", %rsp\n";
	}

	const assembly::operand EAX = { .Type = assembly::operand_type::Register, .Register = assembly::x64_register::EAX };

	for (const assembly::instruction &Instruction : Function->Instructions) {
		switch (Instruction.Op) {
			case assembly::operation::Mov: {
				EmitMovInstruction(Builder, Instruction.Src1, Instruction.Dst);
			} break;
			case assembly::operation::BitwiseNegate: {
				EmitMovInstruction(Builder, Instruction.Src1, EAX);
				Builder += "  not %eax\n";
				EmitMovInstruction(Builder, EAX, Instruction.Dst);
			} break;
			case assembly::operation::Negate: {
				EmitMovInstruction(Builder, Instruction.Src1, EAX);
				Builder += "  neg %eax\n";
				EmitMovInstruction(Builder, EAX, Instruction.Dst);
			} break;
			case assembly::operation::Return: {
				EmitMovInstruction(Builder, Instruction.Src1, Instruction.Dst);
				if (Function->StackSize > 0) {
					Builder += "  movq %rbp, %rsp\n"
							"  popq %rbp\n";
				}
				Builder += "  ret\n";
			} break;
			default:
				break;
		}
	}

	Builder += ".section .note.GNU-stack,\"\", @progbits\n";

	string8 FinalString = Builder.FinalizeString();
	ssize_t BytesWritten = write(FileDescriptor, FinalString.Data, FinalString.Length);
	if (BytesWritten < 0) {
		PrintError("Failed to write to file: %s", Path);
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
			BitwiseNegate,
			Add,
			Subtract
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

static ir::operand EmitExpressionIR(ir::function *Function, ast_node *ExpressionNode) {
	switch (ExpressionNode->Type) {
		case ast_node_type::IntConstant: {
			return { ir::operand::type::Constant, ExpressionNode->IntValue };
		}
		case ast_node_type::UnaryNegate:
		case ast_node_type::UnaryBitwiseNegate: {
			ir::operand Src = EmitExpressionIR(Function, ExpressionNode->UnaryOperation.Expression);
			ir::operand Dst = { ir::operand::type::Temp, Function->TempCount++ };
			ir::instruction::opcode Opcode = (ExpressionNode->Type == ast_node_type::UnaryNegate)
				? ir::instruction::opcode::Negate : ir::instruction::opcode::BitwiseNegate;
			ir::instruction NewInstruction = { .Opcode = Opcode, .Dst = Dst, .Src1 = Src, };
			Function->Instructions.Push(NewInstruction);
			return Dst;
		}
		case ast_node_type::Add:
		case ast_node_type::Subtract: {
			ir::operand Left = EmitExpressionIR(Function, ExpressionNode->BinaryOperation.Left);
			ir::operand Right = EmitExpressionIR(Function, ExpressionNode->BinaryOperation.Right);
			ir::instruction::opcode Opcode = (ExpressionNode->Type == ast_node_type::Add)
				? ir::instruction::opcode::Add : ir::instruction::opcode::Subtract;
			ir::operand Dst = { ir::operand::type::Temp, Function->TempCount++ };
			ir::instruction NewInstruction = { .Opcode = Opcode, .Dst = Dst, .Src1 = Left, .Src2 = Right };
			Function->Instructions.Push(NewInstruction);
			return Dst;
		}
		default:;
	}

	return {};
}

static ir::function EmitIR(memory_arena *Arena, const linked_list<ast_function_declaration> &Node) {
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

static assembly::operand IROperandToAssemblyOperand(const ir::operand &IROperand) {
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

static void PrintAssemblyInstructions(const assembly::function &Function) {
	arena_auto_pop DeferredPop(&Temp);

	auto PrintOperand = [&](const assembly::operand &Op, string8_builder &Builder) {
		switch (Op.Type) {
			case assembly::operand_type::Immediate: {
				Builder.FormatAndPush("${}", Op.ImmediateValue);
			} break;
			case assembly::operand_type::Register:
				switch (Op.Register) {
					case assembly::x64_register::EAX: Builder += "%rax"; break;
					case assembly::x64_register::R10D: Builder += "%r10"; break;
				} break;
			case assembly::operand_type::StackLocation: {
				Builder.FormatAndPush("{}(%rsp)", Op.StackLocation);
			} break;
			default:;
		}
	};

	string8_builder Builder(&Temp);
	for (const assembly::instruction &Instruction : Function.Instructions) {
		switch (Instruction.Op) {
			case assembly::operation::Negate: {
				Builder += "negate ";
				PrintOperand(Instruction.Src1, Builder);
				Builder += " -> ";
				PrintOperand(Instruction.Dst, Builder);
				Builder += "\n";
			} break;
			case assembly::operation::BitwiseNegate: {
				Builder += "bitwise_negate ";
				PrintOperand(Instruction.Src1, Builder);
				Builder += " -> ";
				PrintOperand(Instruction.Dst, Builder);
				Builder += "\n";
			} break;
			case assembly::operation::Return: {
				Builder += "return ";
				PrintOperand(Instruction.Src1, Builder);
				Builder += " -> ";
				PrintOperand(Instruction.Dst, Builder);
				Builder += "\n";
			} break;
			default: {
			} break;
		}
	}
	Print(Builder.FinalizeString());
}

static assembly::function IRFunctionToAssembly(memory_arena *Arena, const ir::function &Function) {
	assembly::function Result;
	Result.Instructions = linked_list<assembly::instruction>(Arena);
	Result.Name = Function.Name;
	Result.StackSize = Function.TempCount * 8;

	for (const ir::instruction &Instruction : Function.Instructions) {
		assembly::instruction AssemblyInstruction = {};
		switch (Instruction.Opcode) {
			case ir::instruction::opcode::Negate: {
				AssemblyInstruction.Op = assembly::operation::Negate;
				AssemblyInstruction.Src1 = IROperandToAssemblyOperand(Instruction.Src1);
				AssemblyInstruction.Dst = IROperandToAssemblyOperand(Instruction.Dst);
			} break;
			case ir::instruction::opcode::BitwiseNegate: {
				AssemblyInstruction.Op = assembly::operation::BitwiseNegate;
				AssemblyInstruction.Src1 = IROperandToAssemblyOperand(Instruction.Src1);
				AssemblyInstruction.Dst = IROperandToAssemblyOperand(Instruction.Dst);
			} break;
			case ir::instruction::opcode::Return: {
				AssemblyInstruction.Op = assembly::operation::Return;
				AssemblyInstruction.Dst = { .Type = assembly::operand_type::Register, .Register = assembly::x64_register::EAX };
				AssemblyInstruction.Src1 = IROperandToAssemblyOperand(Instruction.Src1);
			} break;
			case ir::instruction::opcode::Add: {
				AssemblyInstruction.Op = assembly::operation::Add;
				AssemblyInstruction.Src1 = IROperandToAssemblyOperand(Instruction.Src1);
				AssemblyInstruction.Src2 = IROperandToAssemblyOperand(Instruction.Src2);
				AssemblyInstruction.Dst = IROperandToAssemblyOperand(Instruction.Dst);
			} break;
			case ir::instruction::opcode::Subtract: {
				AssemblyInstruction.Op = assembly::operation::Subtract;
				AssemblyInstruction.Src1 = IROperandToAssemblyOperand(Instruction.Src1);
				AssemblyInstruction.Src2 = IROperandToAssemblyOperand(Instruction.Src2);
				AssemblyInstruction.Dst = IROperandToAssemblyOperand(Instruction.Dst);
			} break;
			default: {
				assert(false);
				continue;
			}
		}
		Result.Instructions.Push(AssemblyInstruction);
	}

#if 1
	PrintAssemblyInstructions(Result);
#endif

	return Result;
}

struct tokenizer_error {
	string8 ErrorMessage;
	string8 Line;
	u32 ColumnIndex;
	u32 LineNumber;
};

using tokenizer_result = value_or_error<linked_list<token>, tokenizer_error>;
tokenizer_result Tokenize(memory_arena *Arena, const string8 &FileContents) {

	linked_list<token> TokenList(Arena);

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
	u32 LineStartIndex = 0;

	const auto CreateError = [&](const string8 &Message, u32 CurrentColumnIndex) -> tokenizer_error {
		tokenizer_error Result = {};

		Result.ErrorMessage = Message;
		Result.ColumnIndex = CurrentColumnIndex - LineStartIndex;
		Result.LineNumber = LineNumber;

		u32 Index = CurrentColumnIndex;
		while (FileContents[Index + 1] != 0 && FileContents[Index + 1] != '\n') {
			Index += 1;
		}
		Result.Line = FileContents.Substring(LineStartIndex, Index);

		return Result;
	};

	const auto CreateLineString8 = [&](u32 CurrentColumnIndex) -> string8 {
		u32 Index = CurrentColumnIndex;

		while (FileContents[Index + 1] != 0 && FileContents[Index + 1] != '\n') {
			Index += 1;
		}
		return FileContents.Substring(LineStartIndex, Index);
	};

	for (u32 i = 0; i < FileContents.Length;) {
		char8 c = FileContents[i];

		if (IsWhitespace(c)) {
			if (c == '\n') {
				LineStartIndex = i + 1;
				LineNumber += 1;
			}
			i += 1;
			continue;
		}

		if (IsAlpha(c)) {
			u32 StartIndex = i;
			do {
				i += 1;
			} while (IsAlphaNumeric(FileContents[i]));

			if (!IsWhitespace(FileContents[i]) && !CharTable[FileContents[i]]) {
				return CreateError("Invalid character after identifer or keyword", i);
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

			if (!IsWhitespace(FileContents[i]) && !CharTable[FileContents[i]] || IsAlpha(FileContents[i])) {
				return CreateError("Invalid character in numeric constant", i);
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

		return CreateError("Unexpected character", i);
	}

	return TokenList;
};

value_or_error<assembly::function, bool> CompileSourceCode(string8 SourceCode, bool ShowErrors, memory_arena *Arena) {
	tokenizer_result TokenizerResult = Tokenize(Arena, SourceCode);
	if (TokenizerResult.HasError) {
		if (ShowErrors) {
			const tokenizer_error &Error = TokenizerResult.Error;

			char8 *GapString = Temp.PushArray<char8>(Error.ColumnIndex);
			for (u32 i = 0; i < Error.ColumnIndex; ++i) {
				GapString[i] = ' ';
			}
			string8 Gap = { GapString, Error.ColumnIndex };

			Print(
				"{} on line {}\n"
				"{}\n"
				"{}^\n",
				Error.ErrorMessage, Error.LineNumber,
				Error.Line,
				Gap
			);
		}
		return false;
	}
	const linked_list<token> &TokenList = TokenizerResult.Value;

	parser_state ParserState = {
		.Arena = Arena,
		.Current = TokenList.begin()
	};
	parse_result ParseResult = ParseProgram(&ParserState);
	if (ParseResult.HasError) {
		if (ShowErrors) {
			Print("Parse Error: {}\n", ParseResult.Error.Message);
		}
		return false;
	}
	ir::function IRFunction = EmitIR(Arena, ParseResult.Value);
	assembly::function AssemblyFunction = IRFunctionToAssembly(Arena, IRFunction);

	return AssemblyFunction;
}

void CompileFile(string8 FilePath) {
	memory_arena Arena = {};
	Arena.Init(MB(256));
	OnScopeExit(Temp.Reset());

	string8 FileContents = LoadPreprocessedFile(&Arena, FilePath);
	auto AssemblyFunctionOrError = CompileSourceCode(FileContents, true, &Arena);

	if (AssemblyFunctionOrError.HasError) {
		return;
	}

	assembly::function AssemblyFunction = AssemblyFunctionOrError.Value;

	constexpr string8 OutputFileName = string8(u8"output.s");
	EmitAssemblyToFile(&AssemblyFunction, OutputFileName);
}

#ifdef RUN_UNIT_TESTS
bool CompileUnitTest(string8 SourceCode, s32 ExpectedResult) {
	memory_arena Arena = {};
	Arena.Init(MB(256));
	OnScopeExit(Temp.Reset());

	auto AssemblyFunctionOrError = CompileSourceCode(SourceCode, ShowCompilerErrorsInUnitTests, &Arena);

	if (AssemblyFunctionOrError.HasError) {
		return false;
	}

	assembly::function AssemblyFunction = AssemblyFunctionOrError.Value;
	Xbyak::CodeGenerator CodeGenerator;
	LiveJITAssembly(&AssemblyFunction, CodeGenerator);

	main_function_type Main = CodeGenerator.getCode<main_function_type>();
	s32 Result = Main();
	if (Result != ExpectedResult) {
		char *SourceCodeCString = SourceCode.ToCString(&Arena);
		Print("\n{}Expected: {}\nReturned: {}\n", SourceCodeCString, ExpectedResult, Result);
		return false;
	}

	return true;
}
#endif

s32 main(s32 argc, char **argv) {

	Temp.Init(MB(64));

	constexpr string8 RunUnitTestsCommand = u8"--unit-tests";

	#if RUN_UNIT_TESTS
	constexpr bool UnitTestsEnabled = true;
	#else
	constexpr bool UnitTestsEnabled = false;
	#endif

	bool ExecuteUnitTests = false;

	string8 FilePath;

	for (s32 i = 1; i < argc; ++i) {
		string8 CommandLineArgument = (char8 *)argv[i];
		if (UnitTestsEnabled && string8::AreEqual(RunUnitTestsCommand, CommandLineArgument)) {
			ExecuteUnitTests = true;
			continue;
		}

		if (CommandLineArgument.EndsWith(".c")) {
			FilePath = CommandLineArgument;
			continue;
		}
	}

	if (!ExecuteUnitTests && FilePath.Length == 0) {
		PrintError("No input file provided");
	}

#ifdef RUN_UNIT_TESTS
	if (ExecuteUnitTests && ExecuteUnitTests) {
		Print(ANSI_YELLOW "Unit tests enabled\n" ANSI_RESET);

		constexpr bool SetBreakpoint = true;
		constexpr u32 BreakpointIndex = ArrayLen(UnitTestsPass) - 1;

		for (u32 i = 0; i < ArrayLen(UnitTestsPass); ++i) {
			if (SetBreakpoint && BreakpointIndex == i) {
				int volatile k = 1;
			}
			const unit_test &UnitTest = UnitTestsPass[i];
			bool Result = CompileUnitTest(UnitTest.SourceCode, UnitTest.ExpectedResult);
			assert(Result == true);
			Temp.Reset();
		}

		for (const string8 &UnitTest : UnitTestsFail) {
			bool Result = CompileUnitTest(UnitTest, 0);
			assert(Result == false);
			Temp.Reset();
		}
		Print(ANSI_GREEN "All unit tests passed!\n" ANSI_RESET);
	}
#endif

	if (FilePath.Length > 0) {
		Print("Compiling File: {}", FilePath);
		CompileFile(FilePath);
		Temp.Reset();
	}

	return 0;
}
