from ida_bytes import *
from idaapi import *
from idc import *
import idaapi
import ida_bytes
import idc
import binascii

def is_amd64_idb():

	if ida_idp.ph.id != ida_idp.PLFM_386:
		return False
	return ida_ida.cvar.inf.is_64bit()

def get_mask(val):

	result = 0
	while val != 0:
		result |= 1 << val
		val -= 1
		
	result >>= 1
	return result

def resolve(ea):

	mask = get_operand_value(ea, 2) # grab mask reg number
	old_ea = ea
	insn_counter = 0
	while insn_counter < 30: # unsafe value, lower can't catch all... :/
		insn_counter += 1
		ea = prev_head(ea, 0)
		if print_insn_mnem(ea) == "mov" and get_operand_type(ea, 1) == 5 and get_operand_value(ea, 0) == mask: # mov x,imm
			if insn_counter > 15:
				print("WARNING! Mov instruction is more than 15 opcodes before bextr!")
				print("Result can be inaccurate.")
			value = get_operand_value(ea, 1)
			bits  = ((value >> 8) & 0xFF)
			if bits == 0:
				print("EE RR RR OO RR")
				return
			start = value & 0xFF
			bitmask = get_mask(bits)
			is_s = ""
			mask_mode = 1
			if mask_mode == 0:
				if bits > 1:
					is_s = "s"			
				string = "extract {:d} bit" + is_s + ", starting from bit {:d}"
				set_cmt(old_ea, string.format(bits, start), 0)
			else:
				source = print_operand(old_ea, 1)
				dest   = print_operand(old_ea, 0)
				#string = dest + " = " + source + " >> {:d} & 0x{:X}"
				string = source + " >> {:d} & 0x{:X}"
				set_cmt(old_ea, string.format(start, bitmask), 0)
			break
			
	ea = old_ea + 5
	return ea

def single_bextr():

	ea = get_screen_ea()
	opcode = print_insn_mnem(ea)
	if opcode != "bextr":
		print("Selected opcode is not bextr!")
		return

	resolve(ea)
	

def multi_bextr():
	
	ea  = get_first_seg()
	end = get_segm_end(ea) - 0x10

	while ea < BADADDR:
		print(hex(ea))
		if ea >= end:
			if get_next_seg(ea) != get_segm_end(ea): # if next seg is not right after that one
				ea = get_next_seg(ea)
				end = get_segm_end(ea) - 0x10
					
		if idaapi.getseg(ea).perm & idaapi.SEGPERM_EXEC == 0:
			ea = get_next_seg(ea)
			end = get_segm_end(ea) - 0x10
			
		if print_insn_mnem(ea) != "bextr":
			ea += 1
			continue
		
		ea = resolve(ea)

def start_plg():

	#multi_bextr()
	single_bextr()

class bextr_helper_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL
	comment = "Simplify bextr instruction."
	help = ""
	wanted_name = "Comment bextr"
	wanted_hotkey = "F10"

	def init(self):
		if not is_amd64_idb():
			return ida_idaapi.PLUGIN_SKIP

		return idaapi.PLUGIN_KEEP
	
	def run(self, arg):
		start_plg()
	
	def term(self):
		pass

def PLUGIN_ENTRY():
	return bextr_helper_t()
