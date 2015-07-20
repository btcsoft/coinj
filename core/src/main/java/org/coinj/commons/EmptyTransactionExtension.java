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

import org.bitcoinj.core.Message;
import org.bitcoinj.core.Transaction;
import org.coinj.api.TransactionExtension;
import org.coinj.api.TransactionWireStrategy;

import javax.annotation.Nullable;

/**
 * Date: 5/26/15
 * Time: 12:36 AM
 *
 * @author Mikhail Kulikov
 */
public class EmptyTransactionExtension implements TransactionExtension {

    private static final long serialVersionUID = 1L;

    private final Transaction tx;

    public EmptyTransactionExtension(Transaction tx) {
        this.tx = tx;
    }

    @Override
    public Message getBroadcastMessage() {
        return tx;
    }

    @Override
    public void setWireStrategy(@Nullable TransactionWireStrategy strategy) {}

    @Nullable
    @Override
    public TransactionWireStrategy getWireStrategy() {
        return null;
    }

}
