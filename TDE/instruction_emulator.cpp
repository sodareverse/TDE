#include "instruction_emulator.hpp"

#include <idp.hpp>

namespace instruction
{
	template <typename T>
	bool emulate_action_internal(ud_mnemonic_code mnemonic, T input, T* product)
	{
		switch (mnemonic)
		{
		case UD_Ishl:
			*product = (*product << input);
			return true;

		case UD_Ishr:
			*product = (*product >> input);
			return true;
			
		case UD_Iand:
			*product = (*product & input);
			return true;

		case UD_Ixor:
			*product = (*product ^ input);
			return true;

		case UD_Ior:
			*product = (*product | input);
			return true;
			
		case UD_Inot:
			*product = ~(*product);
			return true;
			
		case UD_Ineg:
			*product = static_cast<T>(-(static_cast<std::make_signed<T>::type>(*product)));
			return true;

		case UD_Isub:
			*product = (*product - input);
			return true;

		case UD_Iadd:
			*product = (*product + input);
			return true;
			
		case UD_Iinc:
			*product = (*product + 1);
			return true;

		case UD_Idec:
			*product = (*product - 1);
			return true;

		default:
			msg("[CodeDevirtualizer] Attempted instruction-emulation (for immediate value) on unsupported mnemonic.\n");
			break;
		}

		return false;
	}

	bool emulate(ud_mnemonic_code mnemonic, ud_size size, uint32_t input, uint32_t* product)
	{
		switch (size)
		{
		case UD_SIZE_BYTE:
			return emulate_action_internal<uint8_t>(mnemonic, static_cast<uint8_t>(input), reinterpret_cast<uint8_t*>(product));

		case UD_SIZE_WORD:
			return emulate_action_internal<uint16_t>(mnemonic, static_cast<uint16_t>(input), reinterpret_cast<uint16_t*>(product));

		case UD_SIZE_DWORD:
			return emulate_action_internal<uint32_t>(mnemonic, input, product);

		default:
			msg("[CodeDevirtualizer] Attempted instruction-emulation (for immediate value) on unsupported operand size.\n");
			break;
		}
		
		return false;
	}

	bool emulate_eflags_internal_uint8(ud_mnemonic_code mnemonic, uint8_t input, uint8_t product, uint32_t* eflags)
	{
		switch (mnemonic)
		{
		case UD_Ishl:
			__asm mov al,byte ptr [product]
			__asm mov cl,byte ptr [input]
			__asm shl al,cl
			*eflags = __readeflags();
			return true;

		case UD_Ishr:
			__asm mov al,byte ptr [product]
			__asm mov cl,byte ptr [input]
			__asm shr al,cl
			*eflags = __readeflags();
			return true;
			
		case UD_Iand:
			__asm mov al,byte ptr [product]
			__asm mov cl,byte ptr [input]
			__asm and al,cl
			*eflags = __readeflags();
			return true;

		case UD_Ixor:
			__asm mov al,byte ptr [product]
			__asm mov cl,byte ptr [input]
			__asm xor al,cl
			*eflags = __readeflags();
			return true;

		case UD_Ior:
			__asm mov al,byte ptr [product]
			__asm mov cl,byte ptr [input]
			__asm or al,cl
			*eflags = __readeflags();
			return true;
			
		case UD_Inot:
			__asm mov al,byte ptr [product]
			__asm not al
			*eflags = __readeflags();
			return true;

		case UD_Ineg:
			__asm mov al,byte ptr [product]
			__asm neg al
			*eflags = __readeflags();
			return true;

		case UD_Isub:
			__asm mov al,byte ptr [product]
			__asm mov cl,byte ptr [input]
			__asm sub al,cl
			*eflags = __readeflags();
			return true;

		case UD_Iadd:
			__asm mov al,byte ptr [product]
			__asm mov cl,byte ptr [input]
			__asm add al,cl
			*eflags = __readeflags();
			return true;
			
		case UD_Iinc:
			__asm mov al,byte ptr [product]
			__asm inc al
			*eflags = __readeflags();
			return true;

		case UD_Idec:
			__asm mov al,byte ptr [product]
			__asm dec al
			*eflags = __readeflags();
			return true;

		default:
			msg("[CodeDevirtualizer] Attempted instruction-emulation (for eflags value) on unsupported mnemonic.\n");
			break;
		}

		return false;
	}

	bool emulate_eflags_internal_uint16(ud_mnemonic_code mnemonic, uint16_t input, uint16_t product, uint32_t* eflags)
	{
		switch (mnemonic)
		{
		case UD_Ishl:
			__asm mov ax,word ptr [product]
			__asm mov cl,byte ptr [input]
			__asm shl ax,cl
			*eflags = __readeflags();
			return true;

		case UD_Ishr:
			__asm mov ax,word ptr [product]
			__asm mov cl,byte ptr [input]
			__asm shr ax,cl
			*eflags = __readeflags();
			return true;
			
		case UD_Iand:
			__asm mov ax,word ptr [product]
			__asm mov cx,word ptr [input]
			__asm and ax,cx
			*eflags = __readeflags();
			return true;

		case UD_Ixor:
			__asm mov ax,word ptr [product]
			__asm mov cx,word ptr [input]
			__asm xor ax,cx
			*eflags = __readeflags();
			return true;

		case UD_Ior:
			__asm mov ax,word ptr [product]
			__asm mov cx,word ptr [input]
			__asm or ax,cx
			*eflags = __readeflags();
			return true;
			
		case UD_Inot:
			__asm mov ax,word ptr [product]
			__asm not ax
			*eflags = __readeflags();
			return true;

		case UD_Ineg:
			__asm mov ax,word ptr [product]
			__asm neg ax
			*eflags = __readeflags();
			return true;

		case UD_Isub:
			__asm mov ax,word ptr [product]
			__asm mov cx,word ptr [input]
			__asm sub ax,cx
			*eflags = __readeflags();
			return true;

		case UD_Iadd:
			__asm mov ax,word ptr [product]
			__asm mov cx,word ptr [input]
			__asm add ax,cx
			*eflags = __readeflags();
			return true;

		case UD_Iinc:
			__asm mov ax,word ptr [product]
			__asm inc ax
			*eflags = __readeflags();
			return true;

		case UD_Idec:
			__asm mov ax,word ptr [product]
			__asm dec ax
			*eflags = __readeflags();
			return true;

		default:
			msg("[CodeDevirtualizer] Attempted instruction-emulation (for eflags value) on unsupported mnemonic.\n");
			break;
		}

		return false;
	}

	bool emulate_eflags_internal_uint32(ud_mnemonic_code mnemonic, uint32_t input, uint32_t product, uint32_t* eflags)
	{
		switch (mnemonic)
		{
		case UD_Ishl:
			__asm mov eax,dword ptr [product]
			__asm mov cl,byte ptr [input]
			__asm shl eax,cl
			*eflags = __readeflags();
			return true;

		case UD_Ishr:
			__asm mov eax,dword ptr [product]
			__asm mov cl,byte ptr [input]
			__asm shr eax,cl
			*eflags = __readeflags();
			return true;
			
		case UD_Iand:
			__asm mov eax,dword ptr [product]
			__asm mov ecx,dword ptr [input]
			__asm and eax,ecx
			*eflags = __readeflags();
			return true;

		case UD_Ixor:
			__asm mov eax,dword ptr [product]
			__asm mov ecx,dword ptr [input]
			__asm xor eax,ecx
			*eflags = __readeflags();
			return true;

		case UD_Ior:
			__asm mov eax,dword ptr [product]
			__asm mov ecx,dword ptr [input]
			__asm or eax,ecx
			*eflags = __readeflags();
			return true;

		case UD_Inot:
			__asm mov eax,dword ptr [product]
			__asm not eax
			*eflags = __readeflags();
			return true;

		case UD_Ineg:
			__asm mov eax,dword ptr [product]
			__asm neg eax
			*eflags = __readeflags();
			return true;

		case UD_Isub:
			__asm mov eax,dword ptr [product]
			__asm mov ecx,dword ptr [input]
			__asm sub eax,ecx
			*eflags = __readeflags();
			return true;

		case UD_Iadd:
			__asm mov eax,dword ptr [product]
			__asm mov ecx,dword ptr [input]
			__asm add eax,ecx
			*eflags = __readeflags();
			return true;

		case UD_Iinc:
			__asm mov eax,dword ptr [product]
			__asm inc eax
			*eflags = __readeflags();
			return true;

		case UD_Idec:
			__asm mov eax,dword ptr [product]
			__asm dec eax
			*eflags = __readeflags();
			return true;

		default:
			msg("[CodeDevirtualizer] Attempted instruction-emulation (for eflags value) on unsupported mnemonic.\n");
			break;
		}

		return false;
	}

	bool emulate_eflags(ud_mnemonic_code mnemonic, ud_size size, uint32_t input, uint32_t product, uint32_t* eflags)
	{
		switch (size)
		{
		case UD_SIZE_BYTE:
			return emulate_eflags_internal_uint8(mnemonic, static_cast<uint8_t>(input), static_cast<uint8_t>(product), eflags);

		case UD_SIZE_WORD:
			return emulate_eflags_internal_uint16(mnemonic, static_cast<uint16_t>(input), static_cast<uint16_t>(product), eflags);

		case UD_SIZE_DWORD:
			return emulate_eflags_internal_uint32(mnemonic, input, product, eflags);

		default:
			msg("[CodeDevirtualizer] Attempted instruction-emulation (for eflags value) on unsupported operand size.\n");
			break;
		}
		
		return false;
	}
}