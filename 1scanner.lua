--\bunnyhop-dev/

if not arg[1] then
	print("Usage: lua 1scanner.lua <library>")
	os.exit(1)
end

local libName = arg[1]
print("[+] Library loaded ", libName)

-- store memory's information was found
local foundMemory = {}
local assemblyCache = {}
local libraryInfo = {
	name = libName,
	baseAddress = "0x" .. string.format("%08X", math.random(0x10000000, 0x7FFFFFFF)),
	size = math.random(1024*1024, 10*1024*1024) -- 1MB to 10MB
}

-- x86 assembly instructions and registers
local x86Instructions = {
	"mov", "push", "pop", "call", "ret", "jmp", "cmp", "test", "add", "sub", 
	"mul", "div", "xor", "and", "or", "not", "shl", "shr", "lea", "nop",
	"int", "syscall", "leave", "enter", "inc", "dec", "neg", "imul", "idiv"
}

local x86Registers = {
	"eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
	"ax", "bx", "cx", "dx", "si", "di", "sp", "bp",
	"al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"
}

local function randomHex(length)
	local hexChars = "0123456789ABCDEF"
	local result = ""
	for _ = 1, length do
		local randomIndex = math.random(1, #hexChars)
		result = result .. hexChars:sub(randomIndex, randomIndex)
	end
	return result
end

local function randomAddress()
	return "0x" .. randomHex(8)
end

local function randomHexDump(bytes)
	local dump = ""
	for i = 1, bytes do
		dump = dump .. string.format("%02X ", math.random(0, 255))
	end
	return dump:gsub("%s$", "")
end

local function randomHexPattern()
	local pattern = ""
	for i = 1, 6 do
		pattern = pattern .. string.format("%02X", math.random(0, 255))
		if i < 6 then
			pattern = pattern .. " "
		end
	end
	return pattern
end

local function generateRandomInstruction()
	local instruction = x86Instructions[math.random(#x86Instructions)]
	local reg1 = x86Registers[math.random(#x86Registers)]
	local reg2 = x86Registers[math.random(#x86Registers)]
	local immediate = math.random(0, 0xFFFF)
	
	local patterns = {
		instruction .. " " .. reg1 .. ", " .. reg2,
		instruction .. " " .. reg1 .. ", 0x" .. string.format("%X", immediate),
		instruction .. " " .. reg1,
		instruction .. " [" .. reg1 .. "]",
		instruction .. " [" .. reg1 .. " + 0x" .. string.format("%X", math.random(4, 64)) .. "]",
		instruction .. " dword ptr [" .. reg1 .. "]",
	}
	
	return patterns[math.random(#patterns)]
end

local function generateAssemblyBlock(address, count)
	count = count or 8
	local assembly = {}
	local currentAddr = tonumber(address:sub(3), 16)
	
	for i = 1, count do
		local addr = string.format("0x%08X", currentAddr)
		local instruction = generateRandomInstruction()
		local bytes = randomHexDump(math.random(2, 6))
		
		table.insert(assembly, {
			address = addr,
			bytes = bytes,
			instruction = instruction
		})
		
		currentAddr = currentAddr + math.random(2, 6)
	end
	
	return assembly
end

local function analyzePointer(address)
	local targetAddr = randomAddress()
	local analysis = {
		isPointer = math.random() > 0.3,
		pointsTo = targetAddr,
		type = "unknown",
		permissions = "r--"
	}
	
	if analysis.isPointer then
		local pointerTypes = {"function", "data", "string", "vtable", "stack", "heap"}
		analysis.type = pointerTypes[math.random(#pointerTypes)]
		
		if analysis.type == "function" then
			analysis.permissions = "r-x"
		elseif analysis.type == "data" or analysis.type == "string" then
			analysis.permissions = "rw-"
		elseif analysis.type == "stack" then
			analysis.permissions = "rw-"
			analysis.pointsTo = "0x" .. string.format("%08X", math.random(0x7FFF0000, 0x7FFFFFFF))
		end
	end
	
	return analysis
end

local function generateMemoryDump(baseAddress, targetValue)
	local dump = {}
	local baseNum = tonumber(baseAddress:sub(3), 16)

	for i = 0, 3 do
		local currentAddress = string.format("0x%08X", baseNum + (i * 16))
		local hexValues

		if i == 0 then
			local targetBytes = {}
			for byte in targetValue:gmatch("%S+") do
				table.insert(targetBytes, byte)
			end

			while #targetBytes < 16 do
				table.insert(targetBytes, string.format("%02X", math.random(0, 255)))
			end

			hexValues = table.concat(targetBytes, " ")
		else
			hexValues = randomHexDump(16)
		end

		dump[currentAddress] = hexValues
	end
	return dump
end

local function scanningHex()
	local targetHexValue = randomHexPattern()
	local baseNum = tonumber(libraryInfo.baseAddress:sub(3), 16)
	local randomOffset = math.random(0, libraryInfo.size - 64)
	local foundAddress = randomAddress()
	
	foundMemory[foundAddress] = generateMemoryDump(foundAddress, targetHexValue)
	assemblyCache[foundAddress] = generateAssemblyBlock(foundAddress)

	print("Scanning: " .. libraryInfo.name .. ": " .. targetHexValue)
	print("[+] Found!")
	print(string.format("Address: %s | Value: %s", foundAddress, targetHexValue))
end

local function dumpAddr()
	print("Enter address to dump (e.g., 0x12345678):")
	io.write("> ")
	local inputAddress = io.read()

	if foundMemory[inputAddress] then
		print("Dumping memory from Address: " .. inputAddress .. " size: 64 bytes")

		for address, hexValues in pairs(foundMemory[inputAddress]) do
			print(string.format("%s | %s", address, hexValues))
		end
	else
		local baseNum = tonumber(inputAddress:sub(3), 16)
		if baseNum then
			print("Dumping memory from Address: " .. inputAddress .. " Size: 64 bytes")
			for i = 0, 3 do
				local currentAddress = string.format("0x%08X", baseNum + (i * 16))
				local hexValues = randomHexDump(16)
				print(string.format("%s | %s", currentAddress, hexValues))
			end
		else
			print("Invalid address format! Please use format: 0x12345678")
		end
	end
end

local function disassembleAddress()
	print("Enter address to disassemble (e.g., 0x12345678):")
	io.write("> ")
	local inputAddress = io.read()
	
	print("How many instructions? (default: 8)")
	io.write("> ")
	local countInput = io.read()
	local count = tonumber(countInput) or 8
	
	local assembly
	if assemblyCache[inputAddress] then
		assembly = assemblyCache[inputAddress]
	else
		assembly = generateAssemblyBlock(inputAddress, count)
		assemblyCache[inputAddress] = assembly
	end
	
	print(string.format("\n=== DISASSEMBLY AT %s ===", inputAddress))
	print("ADDRESS    | BYTES      | INSTRUCTION")
	print("-----------|------------|------------------------")
	
	for i = 1, math.min(count, #assembly) do
		local asm = assembly[i]
		print(string.format("%s | %-10s | %s", asm.address, asm.bytes, asm.instruction))
	end
end

local function analyzeAddress()
	print("Enter address to analyze (e.g., 0x12345678):")
	io.write("> ")
	local inputAddress = io.read()
	
	local baseNum = tonumber(inputAddress:sub(3), 16)
	if not baseNum then
		print("Invalid address format!")
		return
	end
	
	print(string.format("\n=== ANALYSIS FOR %s ===", inputAddress))
	
	-- Check if it's a pointer
	local ptrAnalysis = analyzePointer(inputAddress)
	
	if ptrAnalysis.isPointer then
		print(string.format("✓ Pointer detected: %s -> %s", inputAddress, ptrAnalysis.pointsTo))
		print(string.format("  Type: %s", ptrAnalysis.type))
		print(string.format("  Permissions: %s", ptrAnalysis.permissions))
		
		if ptrAnalysis.type == "function" then
			print("  Analysis: Likely function pointer")
			print("  Recommendation: Use disassemble to view function")
		elseif ptrAnalysis.type == "string" then
			print("  Analysis: Likely string pointer")
			print("  Content preview: \"" .. string.char(math.random(65, 90)) .. 
				  string.char(math.random(97, 122)) .. "...\"")
		elseif ptrAnalysis.type == "vtable" then
			print("  Analysis: Virtual function table")
			print("  Contains function pointers for C++ objects")
		end
	else
		print("✗ Not a pointer - likely immediate value or data")
	end
	
	-- Memory region analysis
	local libBase = tonumber(libraryInfo.baseAddress:sub(3), 16)
	local libEnd = libBase + libraryInfo.size
	
	if baseNum >= libBase and baseNum <= libEnd then
		print(string.format("✓ Address is within %s library", libraryInfo.name))
		local offset = baseNum - libBase
		print(string.format("  Offset from base: +0x%X", offset))
	else
		print(string.format("✗ Address is outside %s library", libraryInfo.name))
		if baseNum >= 0x7FFF0000 then
			print("  Region: Likely stack memory")
		elseif baseNum >= 0x10000000 then
			print("  Region: Likely heap memory")
		else
			print("  Region: Unknown/System memory")
		end
	end
	
	-- Show raw bytes
	print("\nRaw bytes at address:")
	local hexBytes = randomHexDump(16)
	print(string.format("  %s | %s", inputAddress, hexBytes))
end

local function scanPointer()
	print("Enter target address to find pointer (e.g., 0x12345678):")
	io.write("> ")
	local targetAddress = io.read()

	local pointerAddress = randomAddress()
	local offsets = {
		"0x" .. randomHex(2),
		"0x" .. randomHex(3),
		"0x" .. randomHex(2)
	}

	print("Scanning for pointers to: " .. targetAddress)
	print("Scanning...")
	print("[!] Found Pointer!")
	print(string.format("Pointer: %s -> %s", pointerAddress, targetAddress))
	print(string.format("Pointer chain: [\"%s\" + %s] + %s] + %s] -> %s", 
		  pointerAddress, offsets[1], offsets[2], offsets[3], targetAddress))

	local pointerValue = string.format("%02X %02X %02X %02X", 
		math.random(0, 255), math.random(0, 255), math.random(0, 255), math.random(0, 255))
	foundMemory[pointerAddress] = generateMemoryDump(pointerAddress, pointerValue)
	assemblyCache[pointerAddress] = generateAssemblyBlock(pointerAddress)
end

local function scanNumber()
	print("Enter number to scan: ")
	io.write("> ")
	local input = io.read()
	local numberToScan = tonumber(input)

	if not numberToScan then
		print("Invalid number!")
		return
	end

	local baseNum = tonumber(libraryInfo.baseAddress:sub(3), 16)
	local randomOffset = math.random(0, libraryInfo.size - 64)
	local foundNumberAddress = string.format("0x%08X", baseNum + randomOffset)
	local numberInHex = string.format("0x%X", numberToScan)

	local numberBytes = string.format("%02X %02X %02X %02X", 
		numberToScan & 0xFF, (numberToScan >> 8) & 0xFF, 
		(numberToScan >> 16) & 0xFF, (numberToScan >> 24) & 0xFF)

	foundMemory[foundNumberAddress] = generateMemoryDump(foundNumberAddress, numberBytes)
	assemblyCache[foundNumberAddress] = generateAssemblyBlock(foundNumberAddress)

	print("Scanning in " .. libraryInfo.name .. " (Integer): " .. numberToScan)
	print("[+] Found!")
	print(string.format("Address: %s | Decimal: %d | Hex: %s", foundNumberAddress, numberToScan, numberInHex))
end

local function showLibraryInfo()
	print("=== LIBRARY INFORMATION ===")
	print(string.format("Name: %s", libraryInfo.name))
	print(string.format("Base Address: %s", libraryInfo.baseAddress))
	print(string.format("Size: %d bytes (%.2f MB)", libraryInfo.size, libraryInfo.size / (1024*1024)))
	print(string.format("Address Range: %s - %s", libraryInfo.baseAddress, 
		  string.format("0x%08X", tonumber(libraryInfo.baseAddress:sub(3), 16) + libraryInfo.size)))
	print(string.format("Architecture: x86"))
	print(string.format("Endianness: Little Endian"))
end

local function showFoundAddresses()
	if next(foundMemory) == nil then
		print("No addresses found yet. Please scan something first.")
		return
	end

	print("=== FOUND ADDRESSES ===")
	print("ADDRESS    | TYPE")
	print("-----------|------------------")
	for address, _ in pairs(foundMemory) do
		local analysis = analyzePointer(address)
		local addressType = analysis.isPointer and ("ptr -> " .. analysis.type) or "data"
		print(string.format("%s | %s", address, addressType))
	end
end

local function main()
	math.randomseed(os.time())

	print(string.format("[+] Target Library: %s", libraryInfo.name))
	print(string.format("[+] Base Address: %s", libraryInfo.baseAddress))
	print(string.format("[+] Library Size: %d bytes (%.2f MB)", libraryInfo.size, libraryInfo.size / (1024*1024)))
	
	while true do
		print("\n============ MENU ============")
		print("[1] SCAN HEX PATTERN")
		print("[2] DUMP ADDRESS")
		print("[3] SCAN POINTER")
		print("[4] SCAN NUMBER")
		print("[5] SHOW FOUND ADDRESSES")
		print("[6] LIBRARY INFO")
		print("[7] DISASSEMBLE ADDRESS")
		print("[8] ANALYZE ADDRESS")
		print("[0] EXIT")
		io.write("\n> ")

		local input = io.read()
		local choice = tonumber(input)

		if choice == 1 then
			scanningHex()
		elseif choice == 2 then
			dumpAddr()
		elseif choice == 3 then
			scanPointer()
		elseif choice == 4 then
			scanNumber()
		elseif choice == 5 then
			showFoundAddresses()
		elseif choice == 6 then
			showLibraryInfo()
		elseif choice == 7 then
			disassembleAddress()
		elseif choice == 8 then
			analyzeAddress()
		elseif choice == 0 then
			break
		else
			print("\nERROR: Invalid choice")
		end

		print("\nPress Enter to continue...")
		io.read()
	end
end

main()
