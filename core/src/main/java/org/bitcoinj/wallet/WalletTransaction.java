/**
 * Copyright 2012 Google Inc.
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

package org.bitcoinj.wallet;

import org.bitcoinj.core.Transaction;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Stores data about a transaction that is only relevant to the {@link org.bitcoinj.core.Wallet} class.
 */
public class WalletTransaction {

    public static final class Pool {

        public static final Pool UNSPENT = new Pool(); // unspent in best chain
        public static final Pool SPENT = new Pool(); // spent in best chain
        public static final Pool DEAD = new Pool(); // double-spend in alt chain
        public static final Pool PENDING = new Pool(); // a pending tx we would like to go into the best chain

        public static Pool createExtension() {
            return new Pool();
        }

        private Pool() {}

    }
    private final Transaction transaction;
    private final Pool pool;
    
    public WalletTransaction(Pool pool, Transaction transaction) {
        this.pool = checkNotNull(pool);
        this.transaction = transaction;
    }

    public Transaction getTransaction() {
        return transaction;
    }
    
    public Pool getPool() {
        return pool;
    }

}

