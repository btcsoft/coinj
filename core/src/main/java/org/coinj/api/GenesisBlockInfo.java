/**
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

package org.coinj.api;

import com.google.common.base.Preconditions;

import static com.google.common.base.Preconditions.checkState;

/**
 * Date: 3/31/15
 * Time: 8:04 PM
 *
 * @author Mikhail Kulikov
 */
public class GenesisBlockInfo {

    public final long genesisBlockDifficultyTarget;
    public final long genesisBlockTime;
    public final long genesisBlockNonce;
    public final String genesisHash;
    public final int genesisBlockValue;
    public final String genesisTxInBytes;
    public final String genesisTxOutBytes;
    public final String genesisMerkleRoot;

    private GenesisBlockInfo(GenesisBlockInfoBuilder builder) {
        Preconditions.checkArgument(builder.genesisBlockDifficultyTarget != 0 && builder.genesisBlockTime != 0 && builder.genesisBlockNonce != 0 && builder.genesisHash != null
                && builder.genesisBlockValue != 0 && builder.genesisTxOutBytes != null, "Properly initialize builder with all values");

        this.genesisBlockDifficultyTarget = builder.genesisBlockDifficultyTarget;
        this.genesisBlockTime = builder.genesisBlockTime;
        this.genesisBlockNonce = builder.genesisBlockNonce;
        this.genesisHash = builder.genesisHash;
        this.genesisBlockValue = builder.genesisBlockValue;
        this.genesisTxInBytes = builder.genesisTxInBytes;
        this.genesisTxOutBytes = builder.genesisTxOutBytes;
        this.genesisMerkleRoot = builder.genesisMerkleRoot;
    }

    public void checkGenesisHash(final String calculatedHash) {
        checkState(genesisHash.equals(calculatedHash), "Genesis hash check failed. Current value: %s, must be: %s.", calculatedHash, genesisHash);
    }

    public static class GenesisBlockInfoBuilder {

        private long genesisBlockDifficultyTarget;
        private long genesisBlockTime;
        private long genesisBlockNonce;
        private String genesisHash;
        private int genesisBlockValue;
        private String genesisTxInBytes;
        private String genesisTxOutBytes;
        private String genesisMerkleRoot;

        public void setGenesisBlockDifficultyTarget(long genesisBlockDifficultyTarget) {
            this.genesisBlockDifficultyTarget = genesisBlockDifficultyTarget;
        }

        public void setGenesisBlockNonce(long genesisBlockNonce) {
            this.genesisBlockNonce = genesisBlockNonce;
        }

        public void setGenesisBlockTime(long genesisBlockTime) {
            this.genesisBlockTime = genesisBlockTime;
        }

        public void setGenesisBlockValue(int genesisBlockValue) {
            this.genesisBlockValue = genesisBlockValue;
        }

        public void setGenesisHash(String genesisHash) {
            this.genesisHash = genesisHash;
        }

        public void setGenesisTxInBytes(String genesisTxInBytes) {
            this.genesisTxInBytes = genesisTxInBytes;
        }

        public void setGenesisTxOutBytes(String genesisTxOutBytes) {
            this.genesisTxOutBytes = genesisTxOutBytes;
        }

        public void setGenesisMerkleRoot(String genesisMerkleRoot) {
            this.genesisMerkleRoot = genesisMerkleRoot;
        }

        public GenesisBlockInfo build() {
            return new GenesisBlockInfo(this);
        }

    }

}
