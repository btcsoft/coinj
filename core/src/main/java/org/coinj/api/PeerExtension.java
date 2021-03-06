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

import org.bitcoinj.core.GetDataMessage;
import org.bitcoinj.core.InventoryItem;
import org.bitcoinj.core.Message;

/**
 * Date: 5/14/15
 * Time: 8:57 PM
 *
 * @author Mikhail Kulikov
 */
public interface PeerExtension {

    public InventoryAccumulator createInventoryAccumulator();

    public void processInv(InventoryAccumulator accumulator, GetDataMessage getDataMessage);

    /**
     * Process extension specific message and do whatever.
     * @param m    extension message.
     * @return     true if type of the message acknowledged by implementation, false otherwise.
     */
    public boolean processMessage(Message m);

    public interface InventoryAccumulator {

        /**
         * Add InventoryItem to process it later.
         * @param item item from inv message.
         * @return true if item have a type that implementation acknowledges, false otherwise.
         */
        public boolean addItem(InventoryItem item);

    }

}
