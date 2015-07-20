/**
 * Copyright 2011 Google Inc.
 * Copyright 2015 BitTechCenter Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core;

import com.google.common.base.Preconditions;
import org.coinj.api.CoinDefinition;

public class InventoryItem {
    
    /**
     * 4 byte uint32 type field + 32 byte hash
     */
    static final int MESSAGE_LENGTH = 36;

    public static final String TYPE_ERROR = "Error";
    public static final String TYPE_TX = "Transaction";
    public static final String TYPE_BLOCK = "Block";
    public static final String TYPE_FILTERED_BLOCK = "FilteredBlock";

    public static final int CODE_ERROR = 0;
    public static final int CODE_TX = 1;
    public static final int CODE_BLOCK = 2;
    public static final int CODE_FILTERED_BLOCK = 3;


    public static InventoryItem createErrorItem(Sha256Hash hash) {
        return new InventoryItem(hash, TYPE_ERROR);
    }

    public static InventoryItem createTransactionItem(Sha256Hash hash) {
        return new InventoryItem(hash, TYPE_TX);
    }

    public static InventoryItem createBlockItem(Sha256Hash hash) {
        return new InventoryItem(hash, TYPE_BLOCK);
    }

    public static InventoryItem createFilteredBlockItem(Sha256Hash hash) {
        return new InventoryItem(hash, TYPE_FILTERED_BLOCK);
    }

    public static InventoryItem createByTypeCode(Sha256Hash hash, int typeCode, CoinDefinition definition) throws ProtocolException {
        final String type;
        switch (typeCode) {
            case CODE_ERROR:
                type = TYPE_ERROR;
                break;
            case CODE_TX:
                type = TYPE_TX;
                break;
            case CODE_BLOCK:
                type = TYPE_BLOCK;
                break;
            case CODE_FILTERED_BLOCK:
                type = TYPE_FILTERED_BLOCK;
                break;
            default:
                final String extendedType = definition.getInventoryTypeByCode(typeCode);
                if (extendedType == null) {
                    throw new ProtocolException("Unknown CInv type: " + typeCode);
                }
                type = extendedType;
        }

        return new InventoryItem(hash, type);
    }

    public static int getTypeOrdinal(String type, CoinDefinition definition) {
        if (type.equals(TYPE_ERROR)) {
            return CODE_ERROR;
        } else if (type.equals(TYPE_TX)) {
            return CODE_TX;
        } else if (type.equals(TYPE_BLOCK)) {
            return CODE_BLOCK;
        } else if (type.equals(TYPE_FILTERED_BLOCK)) {
            return CODE_FILTERED_BLOCK;
        } else {
            final Integer ordinal = definition.getInventoryTypeOrdinal(type);
            if (ordinal == null) {
                throw new ProtocolException("Unknown CInv type name: " + type);
            }
            return ordinal;
        }
    }

    public final String type;
    public final Sha256Hash hash;

    private InventoryItem(Sha256Hash hash, String type) {
        Preconditions.checkArgument(hash != null, "Hash is null");
        this.hash = hash;
        this.type = type;
    }

    @Override
    public String toString() {
        return type + ": " + hash;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        InventoryItem other = (InventoryItem) o;

        return hash.equals(other.hash) && type.equals(other.type);

    }

    @Override
    public int hashCode() {
        int result = type.hashCode();
        result = 31 * result + hash.hashCode();
        return result;
    }

}
