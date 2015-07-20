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
import org.bitcoinj.wallet.WalletTransaction;

import javax.annotation.Nullable;
import java.io.Serializable;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * Date: 5/14/15
 * Time: 11:25 PM
 *
 * @author Mikhail Kulikov
 */
public interface WalletCoinSpecifics extends Serializable {

    @Nullable
    public Map<Sha256Hash, Transaction> getExtendedTransactionPool(WalletTransaction.Pool pool);

    public Iterable<Map<Sha256Hash, Transaction>> getExtendedTransactionPools();

    public Collection<Map<Sha256Hash, Transaction>> getSpendableExtendedPools();

    public Collection<Map<Sha256Hash, Transaction>> getPendingExtendedPools();

    /**
     * View method to internal map's put (or something semantically close).
     * @param pool  pool type.
     * @param key   tx hash as key.
     * @param value tx.
     * @return      previous key.
     * @throws IllegalArgumentException if pool not supported by implementation.
     */
    @Nullable
    public Transaction putTransactionIntoPool(WalletTransaction.Pool pool, Sha256Hash key, Transaction value) throws IllegalArgumentException;

    public void removeTransactionFromAllPools(Sha256Hash key);

    public void addPoolsToSetIfContainKey(Set<WalletTransaction.Pool> set, Sha256Hash key);

    @Nullable
    public Integer getPoolSize(WalletTransaction.Pool pool);

    public int getAllExtendedPoolSizes();

    public void addAllTransactionsFromPools(Set<Transaction> set);

    public void addTransactionsFromAllPoolsToSet(Set<WalletTransaction> set);

    public void processBestBlockForExtendedTypes(Transaction tx, Map<Transaction, TransactionConfidence.Listener.ChangeReason> confidenceChanged);

    public boolean isExtendedConfidenceRelevant(Transaction tx);

    public TransactionConfidence.ConfidenceType commitTxExtendedConfidenceType(Transaction tx);

    @Nullable
    public WalletTransaction.Pool commitTxExtendedPool(Transaction tx);

    public boolean skipTransactionBroadcast(TransactionConfidence.ConfidenceType confidenceType);

    public boolean isTransactionBroadcastable(TransactionConfidence.ConfidenceType confidenceType);

    public boolean receivePendingExtension(Transaction tx, @Nullable Peer peer, @Nullable PeerGroup peerGroup);

    public boolean removePending(Sha256Hash txHash);

    @Nullable
    public TransactionInput.ConnectionResult maybeConnectResults(TransactionInput input);

    public void clearExtendedPools();

    public String getPoolName(WalletTransaction.Pool pool);

}
