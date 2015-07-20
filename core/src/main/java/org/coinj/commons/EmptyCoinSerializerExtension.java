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
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.ProtocolException;
import org.coinj.api.CoinSerializerExtension;

import javax.annotation.Nullable;
import java.util.Map;

/**
 * Date: 5/15/15
 * Time: 10:13 PM
 *
 * @author Mikhail Kulikov
 */
public class EmptyCoinSerializerExtension implements CoinSerializerExtension {

    public static final EmptyCoinSerializerExtension INSTANCE = new EmptyCoinSerializerExtension();

    protected EmptyCoinSerializerExtension() {}

    @Nullable
    @Override
    public Message attemptToMakeMessage(NetworkParameters params, String command, int length, byte[] payloadBytes, byte[] hash, byte[] checksum) throws ProtocolException {
        return null;
    }

    @Override
    public void retrofitNamesMap(Map<Class<? extends Message>, String> names) {}

}
