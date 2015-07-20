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

import org.bitcoinj.core.*;

import javax.annotation.Nullable;
import java.util.List;
import java.util.Map;

/**
 * Date: 4/15/15
 * Time: 7:27 PM
 *
 * @author Mikhail Kulikov
 */
public interface BlockChainExtension {

    /**
     * Validation of added block.
     * @param added new block
     * @param filteredTxHashList contains all transactions
     * @param filteredTxn just a subset
     * @throws org.bitcoinj.core.VerificationException
     */
    public void verifyBlockAddition(Block added, List<Sha256Hash> filteredTxHashList, @Nullable Map<Sha256Hash, Transaction> filteredTxn);

    /**
     * Validation of difficulty transitions.
     * @param prevBlock previous block
     * @param added new block
     * @throws org.bitcoinj.core.VerificationException
     */
    public void verifyDifficultyTransitions(StoredBlock prevBlock, Block added, NetworkParameters params);

    public void onBlockAddition(StoredBlock block);

}
