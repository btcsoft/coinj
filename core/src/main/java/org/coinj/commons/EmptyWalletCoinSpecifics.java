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

package org.coinj.commons;

import com.google.common.collect.ImmutableList;
import org.bitcoinj.core.*;
import org.bitcoinj.wallet.WalletTransaction;
import org.coinj.api.WalletCoinSpecifics;

import javax.annotation.Nullable;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * Date: 5/15/15
 * Time: 10:15 PM
 *
 * @author Mikhail Kulikov
 */
public class EmptyWalletCoinSpecifics implements WalletCoinSpecifics {

    public static final EmptyWalletCoinSpecifics INSTANCE = new EmptyWalletCoinSpecifics();

    private static final long serialVersionUID = 1L;

    protected EmptyWalletCoinSpecifics() {}

    @Override
    public void addAllTransactionsFromPools(Set<Transaction> set) {}

    @Nullable
    @Override
    public Map<Sha256Hash, Transaction> getExtendedTransactionPool(WalletTransaction.Pool pool) {
        return null;
    }

    @Override
    public ImmutableList<Map<Sha256Hash, Transaction>> getSpendableExtendedPools() {
        return getExtendedTransactionPools();
    }

    public ImmutableList<Map<Sha256Hash, Transaction>> getExtendedTransactionPools() {
        return ImmutableList.of();
    }

    @Override
    public Collection<Map<Sha256Hash, Transaction>> getPendingExtendedPools() {
        return ImmutableList.of();
    }

    @Nullable
    @Override
    public Transaction putTransactionIntoPool(WalletTransaction.Pool pool, Sha256Hash key, Transaction value) throws IllegalArgumentException {
        throw new UnsupportedOperationException("This WalletCoinSpecifics is for coins without CoinSpecifics extension hence this code must be unreachable.");
    }

    @Override
    public void removeTransactionFromAllPools(Sha256Hash key) {}

    @Override
    public void addPoolsToSetIfContainKey(Set<WalletTransaction.Pool> set, Sha256Hash key) {}

    @Nullable
    @Override
    public Integer getPoolSize(WalletTransaction.Pool pool) {
        return null;
    }

    @Override
    public int getAllExtendedPoolSizes() {
        return 0;
    }

    @Override
    public void addTransactionsFromAllPoolsToSet(Set<WalletTransaction> set) {}

    @Override
    public void processBestBlockForExtendedTypes(Transaction tx, Map<Transaction, TransactionConfidence.Listener.ChangeReason> confidenceChanged) {}

    @Override
    public boolean isExtendedConfidenceRelevant(Transaction tx) {
        return false;
    }

    @Override
    public TransactionConfidence.ConfidenceType commitTxExtendedConfidenceType(Transaction tx) {
        return TransactionConfidence.ConfidenceType.PENDING; // unnecessary but to not return null (bad for inspections)
    }

    @Override
    @Nullable
    public WalletTransaction.Pool commitTxExtendedPool(Transaction tx) {
        return null;
    }

    @Override
    public boolean skipTransactionBroadcast(TransactionConfidence.ConfidenceType confidenceType) {
        return false;
    }

    @Override
    public boolean isTransactionBroadcastable(TransactionConfidence.ConfidenceType confidenceType) {
        return false;
    }

    @Override
    public boolean receivePendingExtension(Transaction tx, @Nullable Peer peer, @Nullable PeerGroup peerGroup) {
        return true;
    }

    @Override
    public boolean removePending(Sha256Hash txHash) {
        return false;
    }

    @Nullable
    @Override
    public TransactionInput.ConnectionResult maybeConnectResults(TransactionInput input) {
        return null;
    }

    @Override
    public void clearExtendedPools() {}

    @Override
    public String getPoolName(WalletTransaction.Pool pool) {
        return null;
    }

}
