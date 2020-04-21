/* ###
 * IP: GHIDRA
 * REVIEWED: YES
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.pcode.utils;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Symbol;

public class InjectionUtils {

	//All methods return either non-zero length arrays or null
	//zero-length arrays unused for convenience
	public static PcodeOp[] getEntryPcodeOps (Instruction instr) {
		Program program = instr.getProgram();
		Function func = program.getFunctionManager().getFunctionAt(instr.getMinAddress());
		if(func != null) {
			PrototypeModel callingConvention = func.getCallingConvention();
			if (callingConvention == null) {
				callingConvention = program.getCompilerSpec().getDefaultCallingConvention();
			}

			String injectionName = callingConvention.getName() + "@@inject_uponentry";

			PcodeInjectLibrary snippetLibrary = program.getCompilerSpec().getPcodeInjectLibrary();
			InjectPayload payload = snippetLibrary.getPayload(InjectPayload.CALLMECHANISM_TYPE, injectionName, program, null);
			if (payload == null) {
				return null;
			}
			InjectContext con = snippetLibrary.buildInjectContext();
			con.baseAddr = instr.getMinAddress();
			con.nextAddr = con.baseAddr.add(instr.getDefaultFallThroughOffset());
			return payload.getPcode(program, con);
		}
		return null;
	}

	public static PcodeOp[] getReturnPcodeOps (Instruction instr, PcodeOp pcode) {
		Program program = instr.getProgram();
		Varnode val = pcode.getInput(0);
		Address target;
		if (pcode.getOpcode() == PcodeOp.CALL) {
			target = val.getAddress();
		}
		else if (pcode.getOpcode() == PcodeOp.CALLIND) {
			if (val.isAddress()) {
				PcodeInjectLibrary snippetLibrary = program.getCompilerSpec().getPcodeInjectLibrary();
				Symbol[] symbols = program.getSymbolTable().getSymbols(instr.getMinAddress());
				String nm = "";
				for (Symbol sym : symbols) {
					DataTypeSymbol datsym = HighFunctionDBUtil.readOverride(sym);
					if (datsym != null) {
						FunctionSignature dt = (FunctionSignature) datsym.getDataType();
						nm = dt.getGenericCallingConvention().getDeclarationName();
					}
				}
				String injectionName = nm + "@@inject_uponreturn";
				InjectPayload payload = snippetLibrary.getPayload(InjectPayload.CALLMECHANISM_TYPE, injectionName, program, null);
				InjectContext con = snippetLibrary.buildInjectContext();
				con.baseAddr = instr.getMinAddress();
				con.nextAddr = con.baseAddr.add(instr.getDefaultFallThroughOffset());
				return payload.getPcode(program, con);
			}
		}
		return null;
	}

}
