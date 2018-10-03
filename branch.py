import mipsHex.mips_Iasm as mips_iasm

from base.error import *
from base.define import ASM_TYPE, ARCHITECTURE

import idautils
import idc

from Queue import Queue

class BranchManager:
	def __init__(self, arc):
		self.arc = arc
		self.branch_list = None
		self.func_ref_list = None
		self.register_status = dict()

		self.tovisit = []
		self.visited = []

	def isForcedBranch(self, addr):
		case = ['j', 'b']

		if idc.GetMnem(addr) in case:
			return True

		return False

	def isReturned(self, addr):
		case = ['jr']

		if idc.GetMnem(addr) in case and idc.GetOpnd(addr, 0) == '$ra':
			return True

		return False

	def isNearAddr(self, optype):
		if optype == ASM_TYPE['Imm_Near_Addr']:
			return True

		return False

	def havePassed(self, addr, main_flow):
		for s, e in main_flow:
			#print "s : 0x%x, e : 0x%x, addr : 0x%x" % (s, e, addr)
			if s <= addr and addr < e:
				return True

		return False

	def ComputeFlow(self, start, end):
		flow_list = list()			# tuple list
		branch_start = start
		branch_end = end

		current = start
		while current <= end:
			if self.isForcedBranch(current):
				if self.isNearAddr(idc.GetOpType(current, 0)):
					branch_end = idc.NextHead(current, end)
					branch_node = (branch_start, idc.NextHead(branch_end))
					flow_list.append(branch_node)

					if branch_end == end:
						break

					branch_start = idc.LocByName(idc.GetOpnd(current, 0))
					# for solve loop problem
					if self.havePassed(branch_start, flow_list):
						branch_start = idc.NextHead(branch_end, end)
					current = branch_start
					continue

			if self.isReturned(current):
				branch_end = idc.NextHead(current, end)
				branch_node = (branch_start, idc.NextHead(branch_end))
				flow_list.append(branch_node)
				
				return flow_list

			current = idc.NextHead(current, end)

		if branch_start < end:
			flow_list.append((branch_start, end))

		return flow_list

	def GetBranchList(self, start=None, end=None):
		self.branch_list = list()

		current = start
		if self.arc == ARCHITECTURE['MIPS']:
			o_iasm = mips_iasm.MIPS_IAsm()
			branch_obj = o_iasm.mips_asm_class['branch']
			jump_obj = o_iasm.mips_asm_class['jump']

			while current <= end:
				method = 'do_' + idc.GetMnem(current)
				if hasattr(branch_obj, method) or hasattr(jump_obj, method):
					if self.isNearAddr(idc.GetOpType(current, 0)):
						opr = idc.LocByName(idc.GetOpnd(current, 0))
						if opr in self.func_ref_list:
							self.branch_list.append(hex(opr))
					elif self.isNearAddr(idc.GetOpType(current, 1)):
						opr = idc.LocByName(idc.GetOpnd(current, 1))
						if opr in self.func_ref_list:
							self.branch_list.append(hex(opr))
					elif self.isNearAddr(idc.GetOpType(current, 2)):
						opr = idc.LocByName(idc.GetOpnd(current, 2))
						if opr in self.func_ref_list:
							self.branch_list.append(hex(opr))

				current = idc.NextHead(current, end)

		self.branch_list = list(set(self.branch_list))
		self.branch_list.sort()

		return self.branch_list

	def InitRefList(self, start=None, end=None):
		self.func_ref_list = list()
		if start != idc.BADADDR:
			for item in idautils.FuncItems(start):
				# Check reference
				cross_refs = idautils.CodeRefsFrom(item, 1)

				temp_ref_list = list()
				# Convert from generator to list
				for ref in cross_refs:
					temp_ref_list.append(ref)

				# Collect ref_lists except temp_ref_list[0](next address)
				if len(temp_ref_list) >= 2:
					for i in range(1, len(temp_ref_list), 1):
						self.func_ref_list.append(temp_ref_list[i])

		# Deduplication
		temp_ref_list = list(set(self.func_ref_list))
		self.func_ref_list = list()

		self.func_ref_list.append(start)
		for ref in temp_ref_list:
			if ref >= start and ref < end:
				self.func_ref_list.append(ref)

		self.func_ref_list.sort()

	def ConvertTotHexList(self, non_hex):
		hexed = list()

		for item in nonhex:
			hexed.append(hex(item))

		return hexed

	def ConvertToNonHexList(self, hexed):
		non_hex = list()

		for item in hexed:
			non_hex.append(int(item.replace('L', ''), 16))

		return non_hex

	def CreateFlowWay(self, func_addr, branch_link):
		way = list()
		# compute all reference addresses flow
		for addr in self.func_ref_list:
			branch_flow = self.ComputeFlow(addr, func_addr[1])

			# check visited flow and register to flow way 
			for s, e in branch_flow:
				before = self.FindBeforeBranch(s, branch_link)
				if before is None:
					before = s

				t = (before, s, e)
				if t in way:
					continue

				limit = self.SetVisitedBranch(s, e)
				if limit == s:
					# it's processed
					continue

				# function start flow
				if func_addr[0] == s or before is None:
					t = (s, s, limit)
				elif s <= before and before < limit:
					t = (s, s, limit)
				else:
					t = (before, s, limit)

				if t not in way:
					way.append(t)

		# append last branch into the flow way
		way.append((addr, addr, func_addr[1]))

		# sort the flow way by start address
		way.sort(key=lambda tup: tup[1])

		return way

	# compute branchs connection link
	def ComputeBranchLink(self, start, end):
		branch_link = dict()
		if len(self.func_ref_list) != 0:
			link = self.GetBranchList(start, self.func_ref_list[0])
			branch_link[hex(start)] = link
			for i in range(len(self.func_ref_list)):
				if i == len(self.func_ref_list)-1:
					link = self.GetBranchList(self.func_ref_list[i], end)
					branch_link[hex(self.func_ref_list[i])] = link
				else:
					link = self.GetBranchList(self.func_ref_list[i], self.func_ref_list[i+1])
					branch_link[hex(self.func_ref_list[i])] = link
		else:
			branch_link[hex(start)] = list()

		return branch_link

	# ComputeBranchLink + all branch's flows
	def ComputeBranchLinkEx(self, start, end):
		branch_link = self.ComputeBranchLink(start, end)

		visited = list()
		for branch in self.func_ref_list:
			if branch in visited:
				continue

			for s, e in self.ComputeFlow(branch, end):
				for node in self.func_ref_list:
					if s < node and node < e:
						if hex(node) not in branch_link[hex(prev_node)]:
							branch_link[hex(prev_node)].append(hex(node))
							branch_link[hex(prev_node)].sort()

						if node not in visited:
							visited.append(node)

						prev_node = node

					elif s == node:
					 	if node not in visited:
							visited.append(node)

						prev_node = node

					elif node >= e:
						break

		self.func_ref_list.sort()
		visited.sort()

		check_assert("[-] all branchs is not processed", visited == self.func_ref_list)

		return branch_link

	def ComputeBranchDFS(self, graph, root):
		new_flow = list()
		self.tovisit = [root] + self.tovisit
		self.visited = [root] + self.visited

		while self.tovisit:
			u = self.tovisit.pop()

			if u not in self.visited:
				self.visited.append(u)
			
			for v in graph[u]:
				if v not in self.visited+self.tovisit:
					self.tovisit.append(v)
					new_flow.append((u, v))

		return self.visited, new_flow

	def SetVisitedBranch(self, start, end):
		not_visited = start
		if start in self.visited:
			return not_visited

		# start <= addr < end, not visited address
		for addr in self.func_ref_list:
			if start >= addr:
				continue

			not_visited = addr
			if addr >= end:
				break

			if hex(addr) in self.visited:
				break
			else:
				self.tovisit.append(hex(addr))
				self.visited.append(hex(addr))

		return not_visited

	def FindBeforeBranch(self, start, link):
		# 
		for k in link.keys():
			if hex(start) in link[k]:
				return int(k.replace('L', ''), 16)

		return None

	def ReComputeFlowWay(self, way):
		computed = list()
		computed_addr = way[0][1]
		for b, s, e in way:
			if computed_addr < e:
				computed_addr = e
				computed_flow = self.ComputeFlow(s, e)
				if len(computed_flow) == 1:
					computed.append((b, s, e))
				# if jump to prev address, len(computed_flow) is more than 1
				elif computed_flow[1][0] < s:
					computed.append((b, s, e))
				else:
					print computed_flow
					error("[-] Need to remake flow way")
			elif computed_addr == e:
				prev = computed.pop()
				if prev[1] <= s:
					computed.append(prev)
				else:
					computed_flow = self.ComputeFlow(s, e)
					if len(computed_flow) == 1:
						computed.append((b, s, e))
					# if jump to prev address, len(computed_flow) is more than 1
					elif computed_flow[1][0] < s:
						computed.append((b, s, e))
					else:
						print computed_flow
						error("[-] Need to remake flow way")
			else:
				# error("[-] It is not sorted flow way")
				pass

		return computed

	def ArrangeFlowWay(self, way):
		arranged = list()
		last_branch = way[0][1]

		for i in range(len(way)):
			b, s, e = way[i]
			if last_branch != s:
				if last_branch > s:
					s = last_branch
				else:
					arranged.append((last_branch, last_branch, s))

			arranged.append((b, s, e))
			last_branch = e

		return arranged

	def ConvertToBranchQueue(self, branch_list):
		branch_queue = Queue(len(branch_list))
		for b, s, e in branch_list:
			branch_queue.put({'base':int(b), 'start':int(s), 'end':int(e)})

		return branch_queue

	def ComputeBranchProcess(self, func_addr):
		if self.func_ref_list is None:
			self.InitRefList(func_addr[0], func_addr[1])

		self.branch_link = self.ComputeBranchLink(func_addr[0], func_addr[1])

		way = self.CreateFlowWay(func_addr, self.branch_link)
		way = self.ReComputeFlowWay(way)			# need to rename
		way = self.ArrangeFlowWay(way)
		way = self.ConvertToBranchQueue(way)

		return way

	##############################
	# Register status per branch #
	##############################
	def GetRegStatus(self, addr):
		if hex(addr).replace('L', '') in self.register_status.keys():
			return self.register_status[hex(addr).replace('L', '')].copy()

		return None

	def InsertRegStatus(self, addr, o_reg):
		# addr is not stored on o_reg object
		self.register_status[hex(addr).replace('L', '')] = o_reg.copy()

	def ClearRegStatus(self):
		for key in self.register_status.keys():
			self.register_status[key] = None

		self.register_status = dict()
