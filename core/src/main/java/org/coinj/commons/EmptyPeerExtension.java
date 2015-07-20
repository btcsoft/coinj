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

import org.bitcoinj.core.GetDataMessage;
import org.bitcoinj.core.InventoryItem;
import org.bitcoinj.core.Message;
import org.coinj.api.PeerExtension;

/**
 * Date: 5/15/15
 * Time: 10:14 PM
 *
 * @author Mikhail Kulikov
 */
public class EmptyPeerExtension implements PeerExtension {

    public static final EmptyPeerExtension INSTANCE = new EmptyPeerExtension();

    private static final EmptyInventoryAccumulator ACC_INSTANCE = new EmptyInventoryAccumulator();

    protected EmptyPeerExtension() {}

    @Override
    public InventoryAccumulator createInventoryAccumulator() {
        return ACC_INSTANCE;
    }

    @Override
    public void processInv(InventoryAccumulator accumulator, GetDataMessage getDataMessage) {}

    @Override
    public boolean processMessage(Message m) {
        return false;
    }

    public static final class EmptyInventoryAccumulator implements InventoryAccumulator {
        private EmptyInventoryAccumulator() {}

        @Override
        public boolean addItem(InventoryItem item) {
            return false;
        }
    }

}
