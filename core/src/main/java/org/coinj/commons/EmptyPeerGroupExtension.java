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

import org.bitcoinj.core.InventoryItem;
import org.bitcoinj.core.Message;
import org.coinj.api.PeerGroupExtension;

import javax.annotation.Nullable;

/**
 * Date: 5/30/15
 * Time: 12:32 AM
 *
 * @author Mikhail Kulikov
 */
public class EmptyPeerGroupExtension implements PeerGroupExtension {

    public static final EmptyPeerGroupExtension INSTANCE = new EmptyPeerGroupExtension();

    private EmptyPeerGroupExtension() {}

    @Nullable
    @Override
    public Message handleGetDataExtension(InventoryItem item) {
        return null;
    }

}
