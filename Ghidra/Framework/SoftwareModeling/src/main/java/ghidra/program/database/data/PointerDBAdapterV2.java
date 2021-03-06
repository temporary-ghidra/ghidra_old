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
package ghidra.program.database.data;

import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.*;

class PointerDBAdapterV2 extends PointerDBAdapter {
	final static int VERSION = 2;
	
	static final int OLD_PTR_DT_ID_COL = 0;
	static final int OLD_PTR_CATEGORY_COL = 1;
	static final int OLD_PTR_LENGTH_COL = 2;
	static final Schema OLD_SCHEMA = new Schema(PointerDBAdapterV2.VERSION, "Pointer ID", new Class[] {
			LongField.class, LongField.class, ByteField.class }, new String[] { "Data Type ID",
			"Category ID", "Length" });
	
	private Table table;

	PointerDBAdapterV2(DBHandle handle) throws VersionException {
		table = handle.getTable(POINTER_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + POINTER_TABLE_NAME);
		}
		else if (table.getSchema().getVersion() != VERSION) {
			int version = table.getSchema().getVersion();
			if (version < VERSION) {
				throw new VersionException(true);
			}
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	Record translateRecord(Record oldRec) {
		if (oldRec == null) {
			return null;
		}
		Record rec = PointerDBAdapter.SCHEMA.createRecord(oldRec.getKey());
		rec.setLongValue(PTR_DT_ID_COL, oldRec.getLongValue(OLD_PTR_DT_ID_COL));
		rec.setLongValue(PTR_CATEGORY_COL, oldRec.getLongValue(OLD_PTR_CATEGORY_COL));
		rec.setByteValue(PTR_LENGTH_COL, oldRec.getByteValue(OLD_PTR_LENGTH_COL));
		rec.setLongValue(PTR_SHIFT_OFFSET_COL, 0);
		return rec;
	}


	@Override
	Record createRecord(long dataTypeID, long categoryID, int length) throws IOException {
		throw new UnsupportedOperationException();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.data.PointerDBAdapter#getRecord(long)
	 */
	@Override
	Record getRecord(long pointerID) throws IOException {
		return translateRecord(table.getRecord(pointerID));
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.data.PointerDBAdapter#getRecords()
	 */
	@Override
	RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(table.iterator());
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.data.PointerDBAdapter#removeRecord(long)
	 */
	@Override
	boolean removeRecord(long pointerID) throws IOException {
		throw new UnsupportedOperationException();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.data.PointerDBAdapter#updateRecord(ghidra.framework.store.db.Record)
	 */
	@Override
	void updateRecord(Record record) throws IOException {
		throw new UnsupportedOperationException();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.data.PointerDBAdapter#getRecordIdsInCategory(long)
	 */
	@Override
	long[] getRecordIdsInCategory(long categoryID) throws IOException {
		return table.findRecords(new LongField(categoryID), OLD_PTR_CATEGORY_COL);
	}

	/**
	 * @see ghidra.program.database.data.PointerDBAdapter#deleteTable()
	 */
	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(POINTER_TABLE_NAME);
	}
	
}
